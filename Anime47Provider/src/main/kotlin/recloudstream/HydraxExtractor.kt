package recloudstream

/**
 * Hydrax / Abyss.to ("HY" server) extractor.
 *
 * Ported from AbyssVideoDownloader (github.com/abdlhay/AbyssVideoDownloader).
 * The HY server on Anime47 embeds videos from abysscdn.com / playhydrax.com / zplayer.io.
 * Those pages ship a base64 blob called `datas` containing an AES-CTR encrypted JSON
 * payload that, once decrypted, lists CDN "sources" (resolutions). Actual segment bytes
 * are fetched from `{sub}.{domain}/sora/{size}/{token}` where `token` is itself an
 * AES-CTR encrypted+double-base64 path — there is no normal HLS/mp4 URL to hand to
 * a player directly, so we relay through a fake local URL + [HydraxInterceptor] that
 * translates player Range requests into the segment-token protocol on the fly.
 */

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.lagradost.cloudstream3.app
import com.lagradost.cloudstream3.network.CloudflareKiller
import com.lagradost.cloudstream3.utils.ExtractorLink
import com.lagradost.cloudstream3.utils.ExtractorLinkType
import com.lagradost.cloudstream3.utils.Qualities
import com.lagradost.cloudstream3.utils.newExtractorLink
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.Source
import okio.Timeout
import okio.buffer
import java.net.URI
import java.net.URLEncoder
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object HydraxExtractor {

    // mapper riêng cho object này: chỉ khởi tạo 1 lần duy nhất khi class được load (Kotlin
    // "object" là singleton), nên chi phí khởi tạo ObjectMapper không lặp lại ở runtime.
    private val mapper = jacksonObjectMapper()
    const val RELAY_HOST = "hydrax-relay.internal"
    private const val ABYSS_BASE_URL = "https://abysscdn.com"

    // SỬA LỖI (nhất quán/độ tin cậy): mọi request khác trong plugin (getMainPage, search,
    // load, fetchApi, markEpisodeWatched...) đều truyền interceptor = CloudflareKiller()
    // của Anime47Provider để tự động vượt qua trang thách thức Cloudflare (challenge page)
    // nếu domain bật bảo vệ này. Request lấy trang embed Abyss (fetchMp4Metadata) trước đây
    // KHÔNG có interceptor nào — nếu abysscdn.com/playhydrax.com/zplayer.io bật Cloudflare
    // (rất phổ biến với CDN video lậu/free để chống bot), response trả về sẽ là trang HTML
    // challenge thay vì trang embed thật, khiến datasRegex không khớp được gì và getLinks()
    // luôn trả về rỗng cho toàn bộ server HY — âm thầm "server HY không có link" trong khi
    // nguyên nhân thực sự là chưa vượt được Cloudflare. Instance CloudflareKiller là
    // stateless/an toàn khi tái sử dụng nhiều lần, nên tạo 1 lần duy nhất ở cấp object.
    private val cloudflareKiller = CloudflareKiller()

    // HIỆU NĂNG: biên dịch 1 lần duy nhất khi object được load (Kotlin "object" là
    // singleton) thay vì mỗi lần gọi fetchMp4Metadata() — tức mỗi lần lấy link cho
    // 1 server "HY" của 1 tập phim. Cùng tinh thần tối ưu regex đã áp dụng ở
    // Anime47Provider.cdnFixRegex / animeIdRegex và HydraxInterceptor.rangeHeaderRegex.
    private val datasRegex = Regex("""const\s+datas\s*=\s*"([^"]*)"""")

    private val HY_HOSTS = listOf("abysscdn.com", "playhydrax.com", "zplayer.io", "short.ink", "short.icu")

    // SỬA LỖI (timeout không khớp ngân sách thời gian): Anime47Provider.EPISODE_TIMEOUT_MS
    // (35s) được tính dựa trên giả định mỗi lần gọi embed Abyss ở đây tối đa 8s, nhưng
    // trước đây fetchMp4Metadata() vẫn hardcode timeout=15000 cho cả 2 lần gọi (lần đầu +
    // retry) — trường hợp xấu nhất thực tế là 15s (watch-info) + 15s + 15s = 45s, vượt xa
    // 35s và khiến withTimeoutOrNull() ở loadLinks() có thể cắt ngang oan 1 request HY đang
    // tải chậm nhưng vẫn hợp lệ trong giới hạn hợp lý của chính nó. Đưa timeout thực tế về
    // đúng 8s như comment đã mô tả, để tổng trường hợp xấu nhất khớp với ngân sách 35s.
    const val HY_EMBED_TIMEOUT_MS = 8000L

    fun isHydraxUrl(url: String): Boolean {
        val host = runCatching { URI(url).host }.getOrNull() ?: return false
        return HY_HOSTS.any { host.contains(it, ignoreCase = true) }
    }

    // ===================== crypto helpers (mirrors AbyssVideoDownloader's CryptoHelper) =====================
    //
    // SỬA LỖI (nghiêm trọng — server HY luôn trả rỗng): bản trước dùng
    // java.security.MessageDigest MD5 chuẩn cho cả 2 trường hợp string và number
    // (keyForString / keyForNumber). Đối chiếu trực tiếp với
    // AbyssVideoDownloader/src/main/resources/keyGenerator.js (file JS thật mà trang
    // abysscdn.com/playhydrax.com dùng để sinh key, được app gốc chạy qua Rhino JS
    // engine — xem CryptoHelper.getKey() trong AbyssVideoDownloader), phát hiện ra:
    //
    // 1) Khi input là STRING (trường hợp mediaKey = "$user_id:$slug:$md5_id"),
    //    generateKey() trong JS cho kết quả giống hệt MD5 chuẩn trên UTF-8 bytes của
    //    chuỗi đó. Đã verify bằng cách chạy trực tiếp keyGenerator.js gốc qua Node.js
    //    và so với crypto.createHash('md5') cho nhiều độ dài chuỗi khác nhau — khớp
    //    100% mọi trường hợp. Nên keyForString cũ (MD5 chuẩn) đã ĐÚNG, giữ nguyên.
    //
    // 2) Khi input là NUMBER (trường hợp encryptionKey = getKey(totalSize) dùng để
    //    tạo token cho từng segment /mp4/.../$FRAGMENT_SIZE/$index), JS đi vào nhánh
    //    `else` của encoder(): `input = input.toString()` — nhưng (đây là 1 BUG THẬT
    //    SỰ nằm trong chính code JS của Abyss, không phải lỗi port) nhánh này CHỈ gán
    //    lại biến `input` thành chuỗi, KHÔNG gọi stringToBytes(input) như 2 nhánh kia.
    //    bytesToWords() sau đó nhận trực tiếp CHUỖI (không phải mảng byte), và biểu
    //    thức `bytes[byteIndex] << (24 - ...)` chạy trên từng KÝ TỰ của chuỗi thay vì
    //    charCodeAt() của ký tự đó — JS ép kiểu ký tự số ('2','0','9'...) thành giá
    //    trị số tương ứng (Number("2") === 2) khi dùng với toán tử '<<', KHÁC hẳn với
    //    charCodeAt() (mã ASCII của '2' là 50). Kết quả: generateKey(2097152) (number)
    //    ≠ generateKey("2097152") (string) dù cùng giá trị hiển thị — đã verify bằng
    //    cách chạy keyGenerator.js gốc với cả 2 kiểu input và log kết quả khác nhau.
    //
    //    Vì server Abyss (backend sinh token hợp lệ) chắc chắn dùng cùng client-side
    //    logic này để mã hoá path segment, ta PHẢI tái tạo đúng bug này — "sửa" nó về
    //    MD5 chuẩn (như bản cũ keyForNumber làm, bằng 1 cách sai khác) sẽ luôn tạo
    //    token sai, khiến mọi request /sora/... cho server HY bị 403/dữ liệu rác.
    //
    //    keyForNumber cũ (tách từng CHỮ SỐ thành 1 byte số nguyên riêng, vd '2' -> 2)
    //    không khớp bug thật ở trên (vốn dùng char-code-as-number của TOÀN BỘ ký tự,
    //    kể cả non-digit nếu có, và chỉ áp dụng đúng cách JS "<<" ép kiểu) nên cũng
    //    sai, dù tình cờ 1 vài input có thể trùng giá trị số học ở 1 số trường hợp.
    //
    // Đã verify toàn bộ implementation dưới đây bằng cách chạy song song keyGenerator.js
    // gốc qua Node.js và 1 bản port Python 1:1 của thuật toán MD5-biến-thể, đối chiếu
    // 7 test-vector (bao gồm mediaKey dạng string và totalSize dạng number ở nhiều độ
    // dài khác nhau, kể cả 0) — khớp 100%.

    /**
     * Port 1:1 của generateKey() trong keyGenerator.js (AbyssVideoDownloader).
     * Xử lý đúng 2 nhánh input như JS gốc, bao gồm cả bug number-quirk mô tả ở trên.
     * Trả về hex string 32 ký tự (dùng trực tiếp làm key liệu — xem aesCtr*ToIso bên dưới,
     * key AES thực tế = UTF-8 bytes của CHÍNH hex string này, không phải digest nhị phân).
     */
    private fun generateKey(value: Any): String {
        // "words" nhị phân dùng để thay thế bytesToWords của JS, nhưng gộp luôn bước
        // chuyển input -> "byte nguồn" tương ứng với từng nhánh của encoder() gốc.
        val (wordSource, byteLength) = when (value) {
            is String -> {
                // Nhánh String của JS: stringToBytes(input) rồi bytesToWords bình
                // thường trên mảng byte thật (charCodeAt & 0xFF của từng ký tự).
                val bytes = IntArray(value.length) { i -> value[i].code and 0xFF }
                bytes to value.length
            }
            else -> {
                // Nhánh else của JS (number, hoặc bất kỳ kiểu nào khác String/Buffer/
                // Array/Uint8Array): input.toString() rồi bytesToWords chạy TRỰC TIẾP
                // trên chuỗi đó — mỗi "byte" ở đây là ký tự của chuỗi bị ép kiểu số
                // qua toán tử '<<' của JS, TƯƠNG ĐƯƠNG Number(char) cho ký tự số, và
                // NaN->0 cho ký tự không phải số (vd dấu '-' của số âm).
                val s = value.toString()
                val bytes = IntArray(s.length) { i ->
                    s[i].digitToIntOrNull() ?: 0
                }
                bytes to s.length
            }
        }
        return md5VariantHex(wordSource, byteLength)
    }

    // ---- thuật toán MD5-biến-thể của keyGenerator.js, port nguyên khối sang Kotlin ----
    // (calculateHash/2/3/4, endian, bytesToWords, padding) — port từng dòng 1-1 từ JS,
    // KHÔNG dùng java.security.MessageDigest vì cần giữ đúng hành vi bug ở trên cho
    // nhánh number; với nhánh string thì thuật toán này cho kết quả trùng MD5 chuẩn
    // (đã verify), nên dùng chung 1 hàm cho cả 2 trường hợp là an toàn và nhất quán.

    private fun rotl(v: Int, s: Int): Int = (v shl s) or (v ushr (32 - s))

    private fun calc1(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int, t: Int): Int {
        val tmp = a + ((b and c) or (b.inv() and d)) + x + t
        return rotl(tmp, s) + b
    }
    private fun calc2(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int, t: Int): Int {
        val tmp = a + ((b and d) or (c and d.inv())) + x + t
        return rotl(tmp, s) + b
    }
    private fun calc3(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int, t: Int): Int {
        val tmp = a + (b xor c xor d) + x + t
        return rotl(tmp, s) + b
    }
    private fun calc4(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int, t: Int): Int {
        val tmp = a + (c xor (b or d.inv())) + x + t
        return rotl(tmp, s) + b
    }

    private fun md5VariantHex(byteSource: IntArray, byteLength: Int): String {
        val bitLength = 8 * byteLength

        // bytesToWords: mỗi "byte" (0..255, hoặc digit 0..9 cho nhánh number) được xếp
        // vào đúng vị trí bit trong mảng Int32, big-endian trong từng word — y hệt JS.
        val wordCount = (bitLength ushr 5) + 17 // đủ chỗ cho padding + length field, dư an toàn
        val words = IntArray(wordCount)
        for (i in 0 until byteLength) {
            val bitIndex = i * 8
            words[bitIndex ushr 5] = words[bitIndex ushr 5] or (byteSource[i] shl (24 - (bitIndex % 32)))
        }

        // byte-swap từng word trước khi hash (đúng vòng lặp đầu tiên trong encoder() JS)
        for (i in words.indices) {
            words[i] = (0x00ff00ff and rotl(words[i], 8)) or (0xff00ff00.toInt() and rotl(words[i], 24))
        }

        words[bitLength ushr 5] = words[bitLength ushr 5] or (128 shl (bitLength % 32))
        val lengthIndex = 14 + (((bitLength + 64) ushr 9) shl 4)
        words[lengthIndex] = bitLength

        var h1 = 0x67452301
        var h2 = -0x10325477
        var h3 = -0x67452302
        var h4 = 0x10325476

        var i = 0
        while (i < words.size) {
            fun w(k: Int) = if (i + k < words.size) words[i + k] else 0
            val t1 = h1; val t2 = h2; val t3 = h3; val t4 = h4
            var a = t1; var b = t2; var c = t3; var d = t4

            a = calc1(a, b, c, d, w(0), 7, -0x28955b88)
            d = calc1(d, a, b, c, w(1), 12, -0x173848aa)
            c = calc1(c, d, a, b, w(2), 17, 0x242070db)
            b = calc1(b, c, d, a, w(3), 22, -0x3e423112)
            a = calc1(a, b, c, d, w(4), 7, -0xa83f051)
            d = calc1(d, a, b, c, w(5), 12, 0x4787c62a)
            c = calc1(c, d, a, b, w(6), 17, -0x57cfb9ed)
            b = calc1(b, c, d, a, w(7), 22, -0x2b96aff)
            a = calc1(a, b, c, d, w(8), 7, 0x698098d8)
            d = calc1(d, a, b, c, w(9), 12, -0x74bb0851)
            c = calc1(c, d, a, b, w(10), 17, -0xa44f)
            b = calc1(b, c, d, a, w(11), 22, -0x76a32842)
            a = calc1(a, b, c, d, w(12), 7, 0x6b901122)
            d = calc1(d, a, b, c, w(13), 12, -0x2678e6d)
            c = calc1(c, d, a, b, w(14), 17, -0x5986bc72)
            b = calc1(b, c, d, a, w(15), 22, 0x49b40821)

            a = calc2(a, b, c, d, w(1), 5, -0x9e1da9e)
            d = calc2(d, a, b, c, w(6), 9, -0x3fbf4cc0)
            c = calc2(c, d, a, b, w(11), 14, 0x265e5a51)
            b = calc2(b, c, d, a, w(0), 20, -0x16493856)
            a = calc2(a, b, c, d, w(5), 5, -0x29d0efa3)
            d = calc2(d, a, b, c, w(10), 9, 0x2441453)
            c = calc2(c, d, a, b, w(15), 14, -0x275e197f)
            b = calc2(b, c, d, a, w(4), 20, -0x182c0438)
            a = calc2(a, b, c, d, w(9), 5, 0x21e1cde6)
            d = calc2(d, a, b, c, w(14), 9, -0x3cc8f82a)
            c = calc2(c, d, a, b, w(3), 14, -0xb2af279)
            b = calc2(b, c, d, a, w(8), 20, 0x455a14ed)
            a = calc2(a, b, c, d, w(13), 5, -0x561c16fb)
            d = calc2(d, a, b, c, w(2), 9, -0x3105c08)
            c = calc2(c, d, a, b, w(7), 14, 0x676f02d9)
            b = calc2(b, c, d, a, w(12), 20, -0x72d5b376)

            a = calc3(a, b, c, d, w(5), 4, -0x5c6be)
            d = calc3(d, a, b, c, w(8), 11, -0x788e097f)
            c = calc3(c, d, a, b, w(11), 16, 0x6d9d6122)
            b = calc3(b, c, d, a, w(14), 23, -0x21ac7f4)
            a = calc3(a, b, c, d, w(1), 4, -0x5b4115bc)
            d = calc3(d, a, b, c, w(4), 11, 0x4bdecfa9)
            c = calc3(c, d, a, b, w(7), 16, -0x944b4a0)
            b = calc3(b, c, d, a, w(10), 23, -0x41404390)
            a = calc3(a, b, c, d, w(13), 4, 0x289b7ec6)
            d = calc3(d, a, b, c, w(0), 11, -0x155ed806)
            c = calc3(c, d, a, b, w(3), 16, -0x2b10cf7b)
            b = calc3(b, c, d, a, w(6), 23, 0x4881d05)
            a = calc3(a, b, c, d, w(9), 4, -0x262b2fc7)
            d = calc3(d, a, b, c, w(12), 11, -0x1924661b)
            c = calc3(c, d, a, b, w(15), 16, 0x1fa27cf8)
            b = calc3(b, c, d, a, w(2), 23, -0x3b53a99b)

            a = calc4(a, b, c, d, w(0), 6, -0xbd6ddbc)
            d = calc4(d, a, b, c, w(7), 10, 0x432aff97)
            c = calc4(c, d, a, b, w(14), 15, -0x546bdc59)
            b = calc4(b, c, d, a, w(5), 21, -0x36c5fc7)
            a = calc4(a, b, c, d, w(12), 6, 0x655b59c3)
            d = calc4(d, a, b, c, w(3), 10, -0x70f3336e)
            c = calc4(c, d, a, b, w(10), 15, -0x100b83)
            b = calc4(b, c, d, a, w(1), 21, -0x7a7ba22f)
            a = calc4(a, b, c, d, w(8), 6, 0x6fa87e4f)
            d = calc4(d, a, b, c, w(15), 10, -0x1d31920)
            c = calc4(c, d, a, b, w(6), 15, -0x5cfebcec)
            b = calc4(b, c, d, a, w(13), 21, 0x4e0811a1)
            a = calc4(a, b, c, d, w(4), 6, -0x8ac817e)
            d = calc4(d, a, b, c, w(11), 10, -0x42c50dcb)
            c = calc4(c, d, a, b, w(2), 15, 0x2ad7d2bb)
            b = calc4(b, c, d, a, w(9), 21, -0x14792c6f)

            h1 += a; h2 += b; h3 += c; h4 += d
            i += 16
        }

        val out = java.nio.ByteBuffer.allocate(16).order(java.nio.ByteOrder.BIG_ENDIAN)
        for (h in intArrayOf(h1, h2, h3, h4)) {
            out.putInt(endianWord(h))
        }
        return out.array().joinToString("") { "%02x".format(it) }
    }

    private fun endianWord(v: Int): Int =
        (0x00ff00ff and rotl(v, 8)) or (0xff00ff00.toInt() and rotl(v, 24))

    /** getKey() cho Number — dùng đúng nhánh "else" (number-quirk) của JS gốc. */
    private fun keyForNumber(value: Long): String = generateKey(value)

    /** getKey() cho String — nhánh String của JS gốc (tương đương MD5 chuẩn UTF-8). */
    private fun keyForString(value: String): String = generateKey(value)

    private fun aesCtrEncryptToIso(data: String, keyHex: String): String {
        val keyBytes = keyHex.toByteArray(Charsets.UTF_8)
        val iv = keyBytes.copyOfRange(0, 16)
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(iv))
        val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        return String(encrypted, Charsets.ISO_8859_1)
    }

    private fun aesCtrDecryptFromIso(cipherIso: String, keyHex: String): String {
        val keyBytes = keyHex.toByteArray(Charsets.UTF_8)
        val iv = keyBytes.copyOfRange(0, 16)
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(iv))
        val cipherBytes = ByteArray(cipherIso.length) { cipherIso[it].code.toByte() }
        val decrypted = cipher.doFinal(cipherBytes)
        return String(decrypted, Charsets.UTF_8)
    }

    private fun doubleBase64(input: String): String {
        val first = Base64.getEncoder().encodeToString(input.toByteArray(Charsets.ISO_8859_1)).replace("=", "")
        return Base64.getEncoder().encodeToString(first.toByteArray()).replace("=", "")
    }

    // ===================== models =====================

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class Datas(
        val md5_id: Int? = null,
        val media: String? = null,
        val slug: String? = null,
        val user_id: Int? = null
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class SourceEntry(
        val label: String? = null,
        val size: Long? = null,
        val sub: String? = null,
        val res_id: Int? = null
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class Mp4Data(
        val domains: List<String?>? = null,
        val sources: List<SourceEntry?>? = null,
        val slug: String? = null,
        val md5_id: Int? = null
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class VideoData(val mp4: Mp4Data? = null)

    // ===================== id / metadata extraction =====================

    private fun getVideoId(url: String): String? {
        val host = runCatching { URI(url).host }.getOrNull() ?: return url
        return when {
            host.contains("short.ink") || host.contains("short.icu") -> url.substringAfterLast("/")
            host.contains("abysscdn.com") || host.contains("playhydrax.com") || host.contains("zplayer.io") ->
                runCatching {
                    URI(url).query?.split("&")
                        ?.map { it.split("=") }
                        ?.firstOrNull { it.getOrNull(0) == "v" }
                        ?.getOrNull(1)
                }.getOrNull()
            else -> url
        }
    }

    private suspend fun fetchMp4Metadata(videoId: String, referer: String): Mp4Data? {
        val embedUrl = "$ABYSS_BASE_URL/?v=$videoId"
        val headers = mapOf(
            "Referer" to referer,
            "User-Agent" to "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        )

        // HIỆU NĂNG/ĐỘ ỔN ĐỊNH: CDN embed (abysscdn.com) đôi khi trả lỗi 5xx/timeout
        // thoáng qua dưới tải cao. Thử lại tối đa 1 lần (tổng 2 lần gọi) trước khi coi
        // là thất bại thật — giảm tỷ lệ "server HY không có link" giả do mạng chập chờn
        // thay vì lỗi thật sự từ phía Abyss.
        var response = runCatching {
            app.get(embedUrl, headers = headers, interceptor = cloudflareKiller, timeout = HY_EMBED_TIMEOUT_MS)
        }.getOrNull()

        if (response == null || !response.isSuccessful) {
            response = runCatching {
                app.get(embedUrl, headers = headers, interceptor = cloudflareKiller, timeout = HY_EMBED_TIMEOUT_MS)
            }.getOrNull()
        }

        // Fail sớm và rõ ràng nếu Abyss trả lỗi HTTP (404/5xx/rate-limit...) hoặc lỗi
        // mạng cả 2 lần thử, thay vì để regex bên dưới âm thầm không tìm thấy "datas"
        // và trả null mập mờ — phân biệt được "trang embed lỗi" với "trang hợp lệ
        // nhưng đổi cấu trúc HTML".
        if (response == null || !response.isSuccessful) return null
        val html = response.text

        // HIỆU NĂNG: trước đây dùng Jsoup.parse() để dựng toàn bộ cây DOM của trang embed
        // rồi select("script") chỉ để tìm 1 dòng "const datas = ...". Parse DOM cho toàn
        // bộ HTML (bao gồm mọi thẻ, style, script khác) tốn CPU/RAM không cần thiết vì
        // ta chỉ cần đúng 1 giá trị chuỗi nằm trong <script>. Chạy regex trực tiếp trên
        // HTML thô cho kết quả giống hệt (không phụ thuộc cấu trúc DOM) nhưng rẻ hơn
        // nhiều lần, và bỏ được toàn bộ chi phí dựng DOM cho mỗi lần lấy link HY.
        val encodedDatas = datasRegex.find(html)
            ?.groupValues?.get(1) ?: return null

        // SỬA LỖI (ổn định): decode/giải mã/parse JSON có thể ném exception nếu trang
        // embed đổi cấu trúc payload (base64 hỏng, AES key sai do thiếu field, JSON
        // không hợp lệ). Trước đây không có try-catch riêng ở đây khiến lỗi này thoát
        // thẳng khỏi fetchMp4Metadata() dưới dạng exception khó phân biệt với lỗi mạng;
        // caller (getLinks) vẫn bọc catch chung nên không crash app, nhưng coi việc này
        // là "không lấy được metadata" (trả null) là hành vi rõ ràng và nhất quán hơn.
        return runCatching {
            val decodedJson = String(Base64.getDecoder().decode(encodedDatas), Charsets.ISO_8859_1)
            val datas = mapper.readValue(decodedJson, Datas::class.java)
            val encryptedMedia = datas.media ?: return@runCatching null

            val mediaKey = keyForString("${datas.user_id}:${datas.slug}:${datas.md5_id}")
            val decryptedJson = aesCtrDecryptFromIso(encryptedMedia, mediaKey)
            val video = mapper.readValue(decryptedJson, VideoData::class.java)

            video.mp4?.copy(slug = datas.slug, md5_id = datas.md5_id)
        }.getOrNull()
    }

    // ===================== public API =====================

    /**
     * Resolves a HY (Hydrax/Abyss) stream URL into one or more playable [ExtractorLink]s.
     * The returned links point at a local relay host; pair with [HydraxInterceptor] via
     * MainAPI.getVideoInterceptor for playback to work.
     */
    suspend fun getLinks(
        streamUrl: String,
        providerName: String,
        serverName: String?,
        referer: String
    ): List<ExtractorLink> {
        val videoId = getVideoId(streamUrl) ?: return emptyList()
        val mp4 = fetchMp4Metadata(videoId, referer) ?: return emptyList()
        val md5Id = mp4.md5_id ?: return emptyList()
        val domain = mp4.domains?.firstOrNull { !it.isNullOrBlank() } ?: return emptyList()
        val sources = mp4.sources?.filterNotNull().orEmpty()
        val displayBaseName = serverName?.takeIf { it.isNotBlank() } ?: "$providerName HY"

        return sources.mapNotNull { source ->
            val sub = source.sub ?: return@mapNotNull null
            val size = source.size ?: return@mapNotNull null
            val resId = source.res_id ?: return@mapNotNull null
            val baseUrl = "https://$sub.${domain.substringAfter(".")}"
            val relayUrl = buildRelayUrl(baseUrl, md5Id, resId, size)
            val quality = source.label?.filter { it.isDigit() }?.toIntOrNull() ?: Qualities.Unknown.value

            newExtractorLink(
                providerName,
                displayBaseName,
                relayUrl,
                ExtractorLinkType.VIDEO
            ) {
                this.referer = referer
                this.quality = quality
                this.headers = mapOf("Referer" to referer)
            }
        }
    }

    private fun buildRelayUrl(baseUrl: String, md5Id: Int, resId: Int, size: Long): String {
        val encodedBase = URLEncoder.encode(baseUrl, "UTF-8")
        return "https://$RELAY_HOST/video.mp4?base=$encodedBase&md5=$md5Id&res=$resId&size=$size"
    }

    // Dùng lại bởi HydraxInterceptor.SegmentSource để tránh trùng lặp cài đặt crypto
    // (trước đây SegmentSource có bản sao riêng của các hàm này — nguy cơ 2 bản lệch
    // nhau nếu chỉ sửa 1 nơi trong tương lai).
    // HIỆU NĂNG: nhận sẵn `key` đã tính (thay vì `totalSize` thô) để caller có thể cache
    // key theo `totalSize` — key không đổi trong suốt vòng đời 1 SegmentSource/video,
    // nên chỉ cần tính (MD5 digest) đúng 1 lần thay vì mỗi lần gọi cho mỗi segment.
    internal fun tokenForPathWithKey(path: String, key: String): String {
        return doubleBase64(aesCtrEncryptToIso(path, key))
    }

    internal fun keyForTotalSize(totalSize: Long): String = keyForNumber(totalSize)
}

/**
 * Translates player Range requests against the fake `hydrax-relay.internal` host into
 * Abyss's token-chunked segment protocol, streaming segments lazily (no full-file buffering).
 */
object HydraxInterceptor : Interceptor {

    private const val FRAGMENT_SIZE = 2097152L
    // Connection pool lớn hơn mặc định (5) để giữ kết nối tới CDN sống lâu hơn giữa các
    // segment request liên tiếp và cho prefetch chạy song song, tránh phải bắt tay TLS
    // lại từ đầu mỗi lần — đây là phần đóng góp lớn vào độ trễ "chờ lấy link stream lâu".
    // HIỆU NĂNG/ĐỘ ỔN ĐỊNH: bật retryOnConnectionFailure (mặc định OkHttp đã là true,
    // nhưng khai báo tường minh để không phụ thuộc vào default có thể đổi giữa các
    // version OkHttp) để tự động thử lại khi TLS handshake/route thất bại tạm thời
    // (rất thường gặp với CDN video free load cao, hay bị rớt kết nối giữa chừng) —
    // giảm số lần player phải tự retry toàn bộ request từ đầu, giúp luồng phát mượt hơn.
    private val client = OkHttpClient.Builder()
        .connectionPool(okhttp3.ConnectionPool(8, 60, java.util.concurrent.TimeUnit.SECONDS))
        .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(20, java.util.concurrent.TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    // HIỆU NĂNG: trước đây mỗi SegmentSource (tức mỗi request video/mỗi lần player mở
    // kết nối mới) tự tạo Executors.newFixedThreadPool(2) riêng và chỉ shutdown khi
    // close() được gọi. Nếu player không gọi close() trong mọi trường hợp (bị crash,
    // chuyển tập nhanh, exception giữa chừng, seek liên tục tạo Source mới...), các
    // pool cũ bị rò rỉ vĩnh viễn (mỗi cái giữ 2 non-daemon thread sống mãi), khiến ứng
    // dụng ngày càng nặng máy/chậm dần theo thời gian sử dụng. Dùng chung 1 thread pool
    // nhỏ ở cấp singleton cho toàn bộ prefetch của mọi segment, không bao giờ shutdown
    // theo từng instance nữa.
    // HIỆU NĂNG/AN TOÀN: dùng daemon threads (thay vì mặc định non-daemon của
    // newFixedThreadPool) để pool không bao giờ ngăn JVM/app thoát hoặc "treo" tiến
    // trình nếu vòng đời plugin không gọi tới việc dọn executor này. Non-daemon threads
    // giữ ứng dụng chạy ngầm ngay cả khi mọi hoạt động thực sự đã kết thúc.
    // HIỆU NĂNG: nâng từ 3 lên 4 thread để khớp hơn với ConnectionPool(8, ...) phía
    // trên — vẫn chừa đủ chỗ trong pool cho các kết nối "đọc trực tiếp" (không phải
    // prefetch) của nhiều SegmentSource hoạt động đồng thời (vd. nhiều tập tải song
    // song), tránh tranh chấp kết nối khiến cả prefetch lẫn đọc trực tiếp đều chậm lại.
    private val prefetchExecutor = java.util.concurrent.Executors.newFixedThreadPool(4) { runnable ->
        Thread(runnable, "hydrax-prefetch").apply { isDaemon = true }
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.url.host != HydraxExtractor.RELAY_HOST) {
            return chain.proceed(request)
        }

        val baseUrl = request.url.queryParameter("base")
        val md5Id = request.url.queryParameter("md5")?.toIntOrNull()
        val resId = request.url.queryParameter("res")?.toIntOrNull()
        val size = request.url.queryParameter("size")?.toLongOrNull()

        if (baseUrl == null || md5Id == null || resId == null || size == null) {
            return errorResponse(request, 500, "Missing relay parameters")
        }

        val rangeHeader = request.header("Range")
        val (start, endInclusive) = parseRange(rangeHeader, size)
        if (start > endInclusive || start < 0) {
            return errorResponse(request, 416, "Invalid range")
        }

        val segmentSource = SegmentSource(client, baseUrl, md5Id, resId, size, start, endInclusive)
        val contentLength = endInclusive - start + 1
        val body: ResponseBody = segmentSource.buffer()
            .let { buffered -> object : ResponseBody() {
                override fun contentType() = "video/mp4".toMediaTypeOrNull()
                override fun contentLength() = contentLength
                override fun source() = buffered
            } }

        val builder = Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", contentLength.toString())
            .body(body)

        return if (rangeHeader != null) {
            builder.code(206).message("Partial Content")
                .header("Content-Range", "bytes $start-$endInclusive/$size")
                .build()
        } else {
            builder.code(200).message("OK").build()
        }
    }

    // HIỆU NĂNG: parseRange() chạy trên MỖI request Range mà player gửi (tức mỗi lần
    // player yêu cầu một đoạn dữ liệu mới trong lúc phát/tua), nên có thể được gọi hàng
    // trăm lần trong 1 phiên xem video. Regex trước đây được new/compile lại mỗi lần gọi
    // — cùng vấn đề đã tối ưu ở Anime47Provider.cdnFixRegex. Đưa lên hằng số cấp object
    // để chỉ biên dịch 1 lần cho toàn bộ vòng đời app.
    private val rangeHeaderRegex = Regex("""bytes=(\d+)-(\d*)""")

    private fun parseRange(header: String?, totalSize: Long): Pair<Long, Long> {
        if (header == null) return 0L to (totalSize - 1)
        val match = rangeHeaderRegex.find(header) ?: return 0L to (totalSize - 1)
        val start = match.groupValues[1].toLongOrNull() ?: 0L
        val end = match.groupValues[2].toLongOrNull() ?: (totalSize - 1)
        return start to minOf(end, totalSize - 1)
    }

    private fun errorResponse(request: Request, code: Int, message: String): Response {
        // SỬA LỖI: thêm Content-Length: 0 tường minh. Một số player/thư viện HTTP đọc
        // strict có thể xử lý sai (chờ vô hạn hoặc lỗi parse) với response không có
        // Content-Length lẫn Transfer-Encoding rõ ràng, dù body rỗng.
        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message(message)
            .header("Content-Length", "0")
            .body("".toResponseBody(null))
            .build()
    }

    /**
     * Lazily streams Abyss segments as the player consumes bytes.
     *
     * Tối ưu độ trễ "vào player rồi loading lâu mới có hình":
     * 1. STREAMING THẬT SỰ (thay đổi quan trọng nhất): bản gốc gọi resp.body.bytes()
     *    — tải nguyên 2MB segment vào RAM rồi mới trả byte đầu tiên cho player, nên
     *    player phải chờ trọn 2MB tải xong mới bắt đầu decode/hiển thị hình. Bản này
     *    giữ kết nối HTTP đang mở (BufferedSource) và forward dữ liệu cho player ngay
     *    khi network trả về, không đợi tải hết segment — giảm đáng kể thời gian tới
     *    byte đầu tiên, đặc biệt quan trọng cho lần load đầu của mỗi video.
     * 2. OkHttpClient dùng chung có connection pool lớn hơn mặc định — tránh phải bắt
     *    tay TLS lại từ đầu cho mỗi segment request.
     * 3. Prefetch: song song với việc đọc segment hiện tại, một coroutine nền tải
     *    trước segment kế tiếp (vẫn dùng cách tải trọn vào RAM vì không cần độ trễ
     *    thấp ở đây — mục tiêu là có sẵn trước khi cần), để giảm giật khi chuyển
     *    giữa các segment 2MB.
     *
     * Lưu ý: kích thước segment (FRAGMENT_SIZE = 2MB) do server Abyss chunk cố định,
     * không thể xin một kích thước nhỏ hơn cho riêng lần tải đầu — nên độ trễ khi bấm
     * play lần đầu (trước khi vào player, lúc lấy metadata + link) vẫn phụ thuộc tốc
     * độ mạng tới abysscdn.com, không thể giảm thêm ở phía client.
     */
    private class SegmentSource(
        private val client: OkHttpClient,
        private val baseUrl: String,
        private val md5Id: Int,
        private val resId: Int,
        private val totalSize: Long,
        startByte: Long,
        private val endByteInclusive: Long
    ) : Source {

        private var currentPos = startByte
        private val currentBuffer = Buffer()

        // Cache segment đã prefetch để không tải lại khi tới lượt đọc thật.
        // HIỆU NĂNG: giới hạn tối đa 4 segment (~8MB) được giữ trong RAM cùng lúc — trước
        // đây không có giới hạn nên nếu prefetch nhanh hơn tốc độ player tiêu thụ (mạng
        // nhanh, CPU decode chậm), map này có thể phình to không kiểm soát.
        private val maxPrefetchCacheEntries = 4
        private val prefetchCache = java.util.concurrent.ConcurrentHashMap<Int, ByteArray>()
        private val prefetchInFlight = java.util.concurrent.ConcurrentHashMap.newKeySet<Int>()
        // Dùng chung executor singleton của HydraxInterceptor thay vì tạo pool riêng cho
        // mỗi SegmentSource (xem ghi chú tại nơi khai báo prefetchExecutor phía trên).
        private val prefetchExecutor = HydraxInterceptor.prefetchExecutor

        // SỬA LỖI (rò rỉ tài nguyên): schedulePrefetch() trước đây gọi
        // prefetchExecutor.submit {} mà KHÔNG lưu lại Future trả về. Khi close() được
        // gọi (player chuyển tập, seek liên tục tạo Source mới, hoặc dừng phát giữa
        // chừng), các task prefetch ĐANG chạy trong background vẫn tiếp tục tải segment
        // 2MB từ CDN dù không còn ai tiêu thụ dữ liệu đó nữa — lãng phí băng thông mạng
        // và giữ pool bận rộn không cần thiết, ảnh hưởng tới các SegmentSource khác đang
        // hoạt động cùng lúc (chia sẻ chung executor). Theo dõi các Future đang chạy để
        // có thể hủy (cancel) chúng ngay khi close().
        private val prefetchFutures = java.util.concurrent.ConcurrentHashMap<Int, java.util.concurrent.Future<*>>()

        // Kết nối HTTP đang mở cho segment hiện tại (đọc dần, KHÔNG tải hết vào RAM
        // trước khi trả cho player — xem ghi chú ở đầu class).
        private var openResponse: Response? = null
        private var openSource: okio.BufferedSource? = null
        private var openSegIndex: Int = -1

        override fun read(sink: Buffer, byteCount: Long): Long {
            if (currentPos > endByteInclusive) return -1L

            val segIndex = (currentPos / FRAGMENT_SIZE).toInt()
            val segStart = segIndex.toLong() * FRAGMENT_SIZE

            // Ưu tiên dữ liệu đã prefetch sẵn trong RAM (đã tải xong từ trước) — trường
            // hợp này copy thẳng, không cần mở connection mới.
            if (currentBuffer.exhausted() && openSegIndex != segIndex) {
                prefetchCache.remove(segIndex)?.let { bytes ->
                    // SỬA LỖI (rò rỉ kết nối): nếu đang có 1 connection HTTP mở dở cho
                    // segment KHÁC (openSegIndex cũ, chưa đọc hết — vd. player vừa seek
                    // sang segIndex này ngay khi nó kịp prefetch xong), trước đây code
                    // ghi đè thẳng openSegIndex = segIndex mà không đóng connection cũ,
                    // khiến socket/response đó bị bỏ quên và không bao giờ đóng cho tới
                    // khi close() của toàn bộ SegmentSource được gọi (nếu có). Đóng nó
                    // trước khi chuyển sang dùng dữ liệu từ cache.
                    if (openSegIndex != -1) {
                        closeOpenConnection()
                    }
                    val offsetInSeg = (currentPos - segStart).toInt().coerceIn(0, bytes.size)
                    currentBuffer.write(bytes, offsetInSeg, bytes.size - offsetInSeg)
                    // HIỆU NĂNG: đánh dấu segment này là "đã có sẵn" bằng cách cập nhật
                    // openSegIndex ngay cả khi dữ liệu đến từ prefetch cache (không phải
                    // từ openSegmentStream()). Trước đây không cập nhật ở đây khiến lần
                    // read() kế tiếp — sau khi currentBuffer bị đọc cạn — hiểu lầm rằng
                    // segment hiện tại "chưa từng mở kết nối" (vì openSegIndex vẫn giữ
                    // giá trị của segment TRƯỚC ĐÓ) và tự ý mở lại 1 connection HTTP mới
                    // để tải LẠI đúng segment vừa lấy từ prefetch, gây lãng phí băng
                    // thông + độ trễ không cần thiết trong lúc phát.
                    openSegIndex = segIndex
                    schedulePrefetch(segIndex + 1)
                }
            }

            if (!currentBuffer.exhausted()) {
                val remaining = endByteInclusive - currentPos + 1
                val toRead = minOf(byteCount, remaining, currentBuffer.size)
                if (toRead <= 0) return -1L
                val read = currentBuffer.read(sink, toRead)
                if (read > 0) currentPos += read
                return read
            }

            // Chưa có sẵn trong buffer/cache: đọc trực tiếp (streaming) từ kết nối HTTP,
            // mở kết nối mới nếu chưa có hoặc đã chuyển sang segment khác.
            //
            // SỬA LỖI (hiệu năng bộ đệm đọc): trước đây `remaining` tính tới
            // endByteInclusive — tức ranh giới của TOÀN BỘ Range mà player yêu cầu, có thể
            // trải dài qua nhiều segment 2MB. Vì openSource chỉ là 1 kết nối HTTP tới ĐÚNG
            // 1 segment hiện tại, việc xin đọc `wantToRead` lớn hơn phần dữ liệu còn lại
            // thực sự có trong segment đó không sai về mặt kết quả (Okio Source.read() chỉ
            // trả về tối đa số byte có sẵn), nhưng khiến Okio phải cấp phát/chuẩn bị bộ đệm
            // lớn hơn cần thiết cho mỗi lần gọi read() ở gần cuối segment. Giới hạn thêm
            // theo `segEndExclusive` (ranh giới thật của segment đang đọc) để mỗi lần đọc
            // luôn khớp đúng với lượng dữ liệu còn lại trong kết nối đang mở.
            val remaining = endByteInclusive - currentPos + 1
            val segEndExclusive = minOf(segStart + FRAGMENT_SIZE, endByteInclusive + 1)
            val remainingInSegment = segEndExclusive - currentPos
            val wantToRead = minOf(byteCount, remaining, remainingInSegment, FRAGMENT_SIZE)

            // SỬA LỖI: Source.skip() của Okio có thể ném IOException nếu kết nối kết
            // thúc/bị gián đoạn trước khi skip đủ số byte yêu cầu (ví dụ server đóng kết
            // nối ngay sau khi mở, hoặc mạng chập chờn giữa lúc mở connection và lúc
            // skip). Trước đây lệnh gọi này không có try-catch, khiến exception thoát
            // thẳng ra khỏi read() và làm crash luồng phát video của player thay vì được
            // xử lý như một lỗi mạng có thể phục hồi. Nếu skip lỗi ngay sau khi mở, coi
            // như read() trực tiếp thất bại (read = -1L, KHÔNG return sớm) để rơi xuống
            // đúng logic retry-1-lần đã có sẵn bên dưới, tận dụng cùng một cơ chế phục
            // hồi thay vì có 2 đường xử lý lỗi tách biệt.
            var read: Long
            if (openSegIndex != segIndex) {
                closeOpenConnection()
                val opened = openSegmentStream(segIndex) ?: return -1L
                openResponse = opened.first
                openSource = opened.second
                openSegIndex = segIndex

                // Bỏ qua phần đầu segment nếu currentPos không trùng đầu segment
                // (trường hợp resume giữa segment sau khi đã đọc một phần).
                val skipBytes = currentPos - segStart
                val skipFailed = if (skipBytes > 0) {
                    try {
                        openSource?.skip(skipBytes)
                        false
                    } catch (e: Exception) {
                        true
                    }
                } else {
                    false
                }

                read = if (skipFailed) {
                    closeOpenConnection()
                    -1L
                } else {
                    try {
                        openSource?.read(sink, wantToRead) ?: -1L
                    } catch (e: Exception) {
                        -1L
                    }
                }
            } else {
                read = try {
                    openSource?.read(sink, wantToRead) ?: -1L
                } catch (e: Exception) {
                    -1L
                }
            }

            // read == -1 có 2 khả năng: (a) đã đọc hết đúng segment này (bình thường,
            // segment cuối cùng của file có thể nhỏ hơn FRAGMENT_SIZE), hoặc (b) kết nối
            // bị gián đoạn giữa chừng trước khi đọc đủ dữ liệu mong đợi. Phân biệt bằng
            // cách so sánh currentPos với ranh giới segment: nếu chưa tới ranh giới mà đã
            // -1, thử mở lại kết nối đúng 1 lần trước khi coi là lỗi thật.
            if (read <= 0) {
                val genuinelyAtSegmentEnd = currentPos >= segEndExclusive
                if (!genuinelyAtSegmentEnd) {
                    closeOpenConnection()
                    val retryOpened = openSegmentStream(segIndex)
                    if (retryOpened != null) {
                        openResponse = retryOpened.first
                        openSource = retryOpened.second
                        openSegIndex = segIndex
                        val skipBytes = currentPos - segStart
                        // SỬA LỖI: cùng vấn đề skip() có thể ném IOException như ở nhánh
                        // mở kết nối lần đầu phía trên — bọc trong try-catch để một lỗi
                        // skip ở lần retry không làm crash toàn bộ read(), mà chỉ khiến
                        // lần đọc này trả về -1L (được xử lý như "hết segment/lỗi không
                        // phục hồi được" ở logic ngay bên dưới).
                        if (skipBytes > 0) {
                            try {
                                openSource?.skip(skipBytes)
                            } catch (e: Exception) {
                                closeOpenConnection()
                            }
                        }
                        read = try {
                            openSource?.read(sink, wantToRead) ?: -1L
                        } catch (e: Exception) {
                            -1L
                        }
                    }
                }
            }

            if (read > 0) {
                currentPos += read
                // Ngay khi bắt đầu đọc segment hiện tại, kích hoạt prefetch cho segment
                // kế tiếp chạy song song trong nền (không dùng chung connection này).
                schedulePrefetch(segIndex + 1)
            } else {
                // Hết segment hiện tại (hoặc lỗi không thể phục hồi) -> đóng connection,
                // lần read() sau sẽ tự mở segment kế tiếp.
                closeOpenConnection()
            }
            return read
        }

        override fun timeout(): Timeout = Timeout.NONE
        override fun close() {
            closeOpenConnection()
            // SỬA LỖI (rò rỉ tài nguyên): hủy mọi prefetch task còn đang chạy trước khi
            // dọn state — xem ghi chú đầy đủ tại khai báo prefetchFutures phía trên.
            // interrupt=true để ngắt cả request HTTP đang chờ phản hồi (blocking I/O),
            // không chỉ các task còn nằm trong hàng đợi chưa bắt đầu.
            prefetchFutures.values.forEach { it.cancel(true) }
            prefetchFutures.clear()
            // KHÔNG shutdown prefetchExecutor ở đây: nó là pool dùng chung (singleton)
            // cho mọi segment/video, không thuộc riêng instance này. Chỉ dọn cache/trạng
            // thái của riêng SegmentSource này.
            prefetchCache.clear()
            prefetchInFlight.clear()
        }

        private fun closeOpenConnection() {
            try {
                openResponse?.close()
            } catch (e: Exception) {
                // ignore
            }
            openResponse = null
            openSource = null
            openSegIndex = -1
        }

        /** Mở kết nối HTTP tới segment nhưng KHÔNG đọc hết body — trả về source để đọc dần. */
        private fun openSegmentStream(index: Int): Pair<Response, okio.BufferedSource>? {
            val path = "/mp4/$md5Id/$resId/$totalSize/$FRAGMENT_SIZE/$index"
            val token = tokenFor(path)
            val segUrl = "$baseUrl/sora/$totalSize/$token"
            val req = Request.Builder()
                .url(segUrl)
                .header("Referer", "https://abysscdn.com/")
                .build()
            return runCatching {
                val resp = client.newCall(req).execute()
                if (!resp.isSuccessful) {
                    resp.close()
                    null
                } else {
                    val source = resp.body?.source()
                    if (source == null) {
                        resp.close()
                        null
                    } else {
                        resp to source
                    }
                }
            }.getOrNull()
        }

        private fun schedulePrefetch(nextIndex: Int) {
            val nextSegStart = nextIndex.toLong() * FRAGMENT_SIZE
            if (nextSegStart > endByteInclusive) return
            if (prefetchCache.containsKey(nextIndex)) return
            // HIỆU NĂNG: không xếp thêm prefetch mới nếu cache đã đầy — tránh tải chồng
            // chất segment vào RAM nhanh hơn player có thể tiêu thụ (đặc biệt khi mạng
            // nhanh hơn tốc độ decode/hiển thị).
            if (prefetchCache.size >= maxPrefetchCacheEntries) return
            if (!prefetchInFlight.add(nextIndex)) return

            val future = prefetchExecutor.submit {
                try {
                    val bytes = fetchSegment(nextIndex)
                    if (bytes.isNotEmpty() && prefetchCache.size < maxPrefetchCacheEntries) {
                        prefetchCache[nextIndex] = bytes
                    }
                } finally {
                    prefetchInFlight.remove(nextIndex)
                    prefetchFutures.remove(nextIndex)
                }
            }
            prefetchFutures[nextIndex] = future
        }

        /** Tải trọn segment vào RAM — dùng riêng cho prefetch chạy nền (không cần độ trễ thấp). */
        private fun fetchSegment(index: Int): ByteArray {
            val path = "/mp4/$md5Id/$resId/$totalSize/$FRAGMENT_SIZE/$index"
            val token = tokenFor(path)
            val segUrl = "$baseUrl/sora/$totalSize/$token"
            val req = Request.Builder()
                .url(segUrl)
                .header("Referer", "https://abysscdn.com/")
                .build()
            return runCatching {
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) ByteArray(0) else resp.body?.bytes() ?: ByteArray(0)
                }
            }.getOrDefault(ByteArray(0))
        }

        // HIỆU NĂNG: key phụ thuộc duy nhất vào `totalSize`, vốn không đổi trong suốt
        // vòng đời của SegmentSource (1 file/1 kết nối phát). Tính 1 lần (MD5 digest)
        // và tái sử dụng cho mọi segment thay vì tính lại ở mỗi lần gọi tokenFor() —
        // tránh lãng phí CPU khi phát các file lớn có hàng chục/hàng trăm segment.
        //
        // Dùng chung HydraxExtractor.tokenForPathWithKey()/keyForTotalSize() (đã gộp
        // crypto helpers vào 1 nơi duy nhất) thay vì giữ bản sao riêng của
        // aesCtrEncryptToIso/doubleBase64 trong class này — tránh 2 cài đặt crypto có
        // thể lệch nhau nếu chỉ 1 bên được sửa trong tương lai.
        private val tokenKey: String by lazy { HydraxExtractor.keyForTotalSize(totalSize) }

        private fun tokenFor(path: String): String =
            HydraxExtractor.tokenForPathWithKey(path, tokenKey)
    }
}
