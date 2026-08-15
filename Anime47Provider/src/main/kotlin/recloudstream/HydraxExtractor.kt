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

import android.util.Log
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

    // TAG dùng để lọc log riêng cho extractor này, vd:
    //   adb logcat -s HydraxExtractor:V
    private const val TAG = "HydraxExtractor"

    private val mapper = jacksonObjectMapper()

    // SỬA LỖI (Connection reset khi TLS handshake): log thực tế cho thấy request tới
    // abyssplayer.com bị "java.net.SocketException: Connection reset" ngay ở bước
    // ConscryptEngineSocket.doHandshake — tức bị chặn/reset trước khi kịp gửi HTTP
    // request, đặc trưng của CDN bật Cloudflare/anti-bot chặn theo TLS fingerprint của
    // client HTTP thuần (không giống trình duyệt thật). CloudflareKiller dùng WebView
    // thật để vượt qua challenge này, giống cách mọi request khác trong plugin
    // (Anime47Provider.interceptor) đã làm cho anime47.best.
    private val cloudflareKiller = CloudflareKiller()
    private const val FRAGMENT_SIZE = 2097152L // 2 MiB, must match server-side chunking
    const val RELAY_HOST = "hydrax-relay.internal"
    // GHI CHÚ: trước đây từng đổi ABYSS_BASE_URL sang "abyssplayer.com" vì test từ máy
    // chủ ở nước ngoài thấy abysscdn.com bị read timeout. Tuy nhiên theo phản hồi thực
    // tế của người dùng: TRƯỚC các commit gần đây, hầu hết server HY vẫn phát được
    // bình thường (chỉ 1 số bộ cụ thể lỗi) — nghĩa là abysscdn.com vẫn hoạt động tốt
    // từ mạng thực tế của họ (VN). Sau khi đổi sang abyssplayer.com, server HY biến
    // mất HOÀN TOÀN khỏi danh sách chọn nguồn (không hiện được link nào), và log cho
    // thấy "Connection reset" ngay lúc TLS handshake tới abyssplayer.com — khả năng
    // cao domain MỚI mới là domain bị chặn/reset từ phía mạng VN, không phải domain
    // gốc. Trả lại abysscdn.com làm domain chính để kiểm chứng lại từ đầu.
    private const val ABYSS_BASE_URL = "https://abysscdn.com"

    // SỬA LỖI (nhận diện host lỗi thời): domain embed Abyss đã đổi từ abysscdn.com
    // sang abyssplayer.com, và short.ink sang short.icu (xác nhận qua log thực tế:
    // "https://abyssplayer.com/xxx" và "https://short.icu/xxx" đều bị isHydraxUrl()
    // trả về false, khiến link HY bị xử lý nhầm thành URL m3u8 trực tiếp thay vì đi
    // qua HydraxExtractor.getLinks() -> player nhận trang embed HTML thay vì file
    // media thật, không phát được). Giữ lại domain cũ phòng trường hợp vẫn dùng song
    // song, chỉ bổ sung domain mới.
    private val HY_HOSTS = listOf(
        "abysscdn.com", "abyssplayer.com",
        "playhydrax.com", "zplayer.io",
        "short.ink", "short.icu"
    )

    fun isHydraxUrl(url: String): Boolean {
        val host = runCatching { URI(url).host }.getOrNull()
        val result = host != null && HY_HOSTS.any { host.contains(it, ignoreCase = true) }
        Log.d(TAG, "isHydraxUrl: url=$url host=$host -> $result")
        return result
    }

    // ===================== crypto helpers (mirrors AbyssVideoDownloader's CryptoHelper) =====================

    private fun md5Hex(bytes: ByteArray): String {
        val digest = java.security.MessageDigest.getInstance("MD5").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    /** getKey() for a Number: each digit char -> its numeric value as a raw byte. */
    private fun keyForNumber(value: Long): String {
        val bytes = value.toString().map { c ->
            if (c.isDigit()) c.digitToInt().toByte() else c.code.toByte()
        }.toByteArray()
        return md5Hex(bytes)
    }

    /** getKey() for a String: plain UTF-8 bytes. */
    private fun keyForString(value: String): String = md5Hex(value.toByteArray(Charsets.UTF_8))

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

    private fun buildSegmentToken(md5Id: Int, resId: Int, size: Long, index: Int): String {
        val path = "/mp4/$md5Id/$resId/$size/$FRAGMENT_SIZE/$index"
        val key = keyForNumber(size)
        return doubleBase64(aesCtrEncryptToIso(path, key))
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
        val host = runCatching { URI(url).host }.getOrNull() ?: return url.also {
            Log.d(TAG, "getVideoId: không parse được host của url=$url, fallback trả về chính url")
        }
        val result = when {
            // SỬA LỖI: abyssplayer.com (domain mới thay abysscdn.com) trả videoId ngay
            // trong path (vd. "https://abyssplayer.com/opymqxBrtY"), không phải qua
            // query "?v=..." như abysscdn.com/playhydrax.com/zplayer.io cũ — cùng dạng
            // với short.ink/short.icu. Xác nhận qua log thực tế.
            host.contains("short.ink") || host.contains("short.icu") || host.contains("abyssplayer.com") ->
                url.substringAfterLast("/")
            host.contains("abysscdn.com") || host.contains("playhydrax.com") || host.contains("zplayer.io") ->
                runCatching {
                    URI(url).query?.split("&")
                        ?.map { it.split("=") }
                        ?.firstOrNull { it.getOrNull(0) == "v" }
                        ?.getOrNull(1)
                }.getOrNull()
            else -> url
        }
        Log.d(TAG, "getVideoId: url=$url host=$host -> videoId=$result")
        return result
    }

    private suspend fun fetchMp4Metadata(videoId: String, referer: String): Mp4Data? {
        // ĐỔI LẠI: abysscdn.com (domain gốc) dùng dạng query "?v=videoId", khác với
        // dạng path "/videoId" của abyssplayer.com — xem ghi chú tại ABYSS_BASE_URL.
        val embedUrl = "$ABYSS_BASE_URL/?v=$videoId"
        Log.d(TAG, "fetchMp4Metadata: videoId=$videoId embedUrl=$embedUrl referer=$referer")

        val response = app.get(
            embedUrl,
            headers = mapOf(
                "Referer" to referer,
                "User-Agent" to "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
            ),
            interceptor = cloudflareKiller,
            timeout = 15000
        )
        Log.d(TAG, "fetchMp4Metadata: HTTP code=${response.code} successful=${response.isSuccessful}")
        val html = response.text
        Log.d(TAG, "fetchMp4Metadata: HTML embed dài ${html.length} ký tự")

        val doc = org.jsoup.Jsoup.parse(html)
        val scriptHtml = doc.select("script").map { it.html() }.firstOrNull { it.contains("datas") }
        if (scriptHtml == null) {
            Log.e(TAG, "fetchMp4Metadata: THẤT BẠI - không tìm thấy thẻ <script> nào chứa 'datas' (trang embed có thể đã đổi cấu trúc, hoặc bị chặn/redirect). 300 ký tự đầu HTML: ${html.take(300)}")
            return null
        }

        val encodedDatas = Regex("""const\s+datas\s*=\s*"([^"]*)"""").find(scriptHtml)
            ?.groupValues?.get(1)
        if (encodedDatas == null) {
            Log.e(TAG, "fetchMp4Metadata: THẤT BẠI - tìm thấy script chứa 'datas' nhưng regex không khớp được giá trị. scriptHtml (300 ký tự đầu): ${scriptHtml.take(300)}")
            return null
        }
        Log.d(TAG, "fetchMp4Metadata: tìm thấy 'datas' (base64, dài ${encodedDatas.length} ký tự)")

        val decodedJson = String(Base64.getDecoder().decode(encodedDatas), Charsets.ISO_8859_1)
        Log.d(TAG, "fetchMp4Metadata: base64-decode datas OK, JSON dài ${decodedJson.length} ký tự")
        val datas = mapper.readValue(decodedJson, Datas::class.java)
        Log.d(TAG, "fetchMp4Metadata: parse Datas OK -> md5_id=${datas.md5_id} slug=${datas.slug} user_id=${datas.user_id} media_len=${datas.media?.length}")
        val encryptedMedia = datas.media
        if (encryptedMedia == null) {
            Log.e(TAG, "fetchMp4Metadata: THẤT BẠI - field 'media' rỗng/null trong datas đã parse")
            return null
        }

        val mediaKey = keyForString("${datas.user_id}:${datas.slug}:${datas.md5_id}")
        val decryptedJson = aesCtrDecryptFromIso(encryptedMedia, mediaKey)
        Log.d(TAG, "fetchMp4Metadata: giải mã AES-CTR OK, JSON video dài ${decryptedJson.length} ký tự")
        val video = mapper.readValue(decryptedJson, VideoData::class.java)

        val result = video.mp4?.copy(slug = datas.slug, md5_id = datas.md5_id)
        if (result == null) {
            Log.e(TAG, "fetchMp4Metadata: THẤT BẠI - field 'mp4' rỗng/null sau khi parse VideoData")
        } else {
            Log.d(TAG, "fetchMp4Metadata: THÀNH CÔNG -> domains=${result.domains} sources_count=${result.sources?.size} md5_id=${result.md5_id}")
        }
        return result
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
        Log.d(TAG, "getLinks: BẮT ĐẦU streamUrl=$streamUrl providerName=$providerName serverName=$serverName referer=$referer")

        val videoId = getVideoId(streamUrl)
        if (videoId == null) {
            Log.e(TAG, "getLinks: DỪNG - getVideoId trả về null cho streamUrl=$streamUrl")
            return emptyList()
        }

        val mp4 = fetchMp4Metadata(videoId, referer)
        if (mp4 == null) {
            Log.e(TAG, "getLinks: DỪNG - fetchMp4Metadata trả về null cho videoId=$videoId (xem log fetchMp4Metadata phía trên để biết bước nào thất bại)")
            return emptyList()
        }

        val md5Id = mp4.md5_id
        if (md5Id == null) {
            Log.e(TAG, "getLinks: DỪNG - mp4.md5_id null")
            return emptyList()
        }

        val domain = mp4.domains?.firstOrNull { !it.isNullOrBlank() }
        if (domain == null) {
            Log.e(TAG, "getLinks: DỪNG - không có domain hợp lệ trong mp4.domains=${mp4.domains}")
            return emptyList()
        }

        val sources = mp4.sources?.filterNotNull().orEmpty()
        Log.d(TAG, "getLinks: md5Id=$md5Id domain=$domain, tổng ${sources.size} sources thô")
        if (sources.isEmpty()) {
            Log.w(TAG, "getLinks: mp4.sources rỗng hoặc toàn null -> sẽ không có link nào được trả về")
        }

        val displayBaseName = serverName?.takeIf { it.isNotBlank() } ?: "$providerName HY"

        val links = sources.mapIndexedNotNull { index, source ->
            val sub = source.sub
            val size = source.size
            val resId = source.res_id
            if (sub == null || size == null || resId == null) {
                Log.w(TAG, "getLinks: bỏ qua source[$index] thiếu field bắt buộc -> sub=$sub size=$size resId=$resId label=${source.label}")
                return@mapIndexedNotNull null
            }
            val baseUrl = "https://$sub.${domain.substringAfter(".")}"
            val relayUrl = buildRelayUrl(baseUrl, md5Id, resId, size)
            val quality = source.label?.filter { it.isDigit() }?.toIntOrNull() ?: Qualities.Unknown.value
            Log.d(TAG, "getLinks: source[$index] label=${source.label} quality=$quality baseUrl=$baseUrl relayUrl=$relayUrl size=$size")

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

        Log.d(TAG, "getLinks: KẾT THÚC - trả về ${links.size}/${sources.size} link hợp lệ cho videoId=$videoId")
        return links
    }

    private fun buildRelayUrl(baseUrl: String, md5Id: Int, resId: Int, size: Long): String {
        val encodedBase = URLEncoder.encode(baseUrl, "UTF-8")
        return "https://$RELAY_HOST/video.mp4?base=$encodedBase&md5=$md5Id&res=$resId&size=$size"
    }
}

/**
 * Translates player Range requests against the fake `hydrax-relay.internal` host into
 * Abyss's token-chunked segment protocol, streaming segments lazily (no full-file buffering).
 */
object HydraxInterceptor : Interceptor {

    private const val TAG = "HydraxInterceptor"
    private const val FRAGMENT_SIZE = 2097152L
    private val client = OkHttpClient()

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.url.host != HydraxExtractor.RELAY_HOST) {
            return chain.proceed(request)
        }

        val baseUrl = request.url.queryParameter("base")
        val md5Id = request.url.queryParameter("md5")?.toIntOrNull()
        val resId = request.url.queryParameter("res")?.toIntOrNull()
        val size = request.url.queryParameter("size")?.toLongOrNull()

        Log.d(TAG, "intercept: relay request rangeHeader=${request.header("Range")} base=$baseUrl md5=$md5Id res=$resId size=$size")

        if (baseUrl == null || md5Id == null || resId == null || size == null) {
            Log.e(TAG, "intercept: THẤT BẠI - thiếu tham số relay bắt buộc (base/md5/res/size), url=${request.url}")
            return errorResponse(request, 500, "Missing relay parameters")
        }

        val rangeHeader = request.header("Range")
        val (start, endInclusive) = parseRange(rangeHeader, size)
        if (start > endInclusive || start < 0) {
            Log.e(TAG, "intercept: THẤT BẠI - range không hợp lệ start=$start endInclusive=$endInclusive size=$size rangeHeader=$rangeHeader")
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

    private fun parseRange(header: String?, totalSize: Long): Pair<Long, Long> {
        if (header == null) return 0L to (totalSize - 1)
        val match = Regex("""bytes=(\d+)-(\d*)""").find(header) ?: return 0L to (totalSize - 1)
        val start = match.groupValues[1].toLongOrNull() ?: 0L
        val end = match.groupValues[2].toLongOrNull() ?: (totalSize - 1)
        return start to minOf(end, totalSize - 1)
    }

    private fun errorResponse(request: Request, code: Int, message: String): Response {
        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message(message)
            .body("".toResponseBody(null))
            .build()
    }

    /** Lazily fetches 2MB Abyss segments as the player consumes bytes, one segment ahead at most. */
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

        override fun read(sink: Buffer, byteCount: Long): Long {
            if (currentPos > endByteInclusive) return -1L

            if (currentBuffer.exhausted()) {
                val segIndex = (currentPos / FRAGMENT_SIZE).toInt()
                val segStart = segIndex.toLong() * FRAGMENT_SIZE
                val segmentBytes = fetchSegment(segIndex)
                if (segmentBytes.isEmpty()) return -1L
                val offsetInSeg = (currentPos - segStart).toInt().coerceIn(0, segmentBytes.size)
                currentBuffer.write(segmentBytes, offsetInSeg, segmentBytes.size - offsetInSeg)
            }

            val remaining = endByteInclusive - currentPos + 1
            val toRead = minOf(byteCount, remaining, currentBuffer.size)
            if (toRead <= 0) return -1L
            val read = currentBuffer.read(sink, toRead)
            if (read > 0) currentPos += read
            return read
        }

        override fun timeout(): Timeout = Timeout.NONE
        override fun close() {}

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
                    if (!resp.isSuccessful) {
                        Log.w(TAG, "fetchSegment: segIndex=$index -> HTTP ${resp.code} không thành công, url=$segUrl")
                        ByteArray(0)
                    } else {
                        resp.body?.bytes() ?: ByteArray(0)
                    }
                }
            }.onFailure { e ->
                Log.w(TAG, "fetchSegment: segIndex=$index EXCEPTION khi tải segment: ${e.message}")
            }.getOrDefault(ByteArray(0))
        }

        private fun tokenFor(path: String): String {
            val key = md5HexOfDigits(totalSize)
            val encrypted = aesCtrEncryptToIso(path, key)
            return doubleBase64(encrypted)
        }

        private fun md5HexOfDigits(value: Long): String {
            val bytes = value.toString().map { c ->
                if (c.isDigit()) c.digitToInt().toByte() else c.code.toByte()
            }.toByteArray()
            val digest = java.security.MessageDigest.getInstance("MD5").digest(bytes)
            return digest.joinToString("") { "%02x".format(it) }
        }

        private fun aesCtrEncryptToIso(data: String, keyHex: String): String {
            val keyBytes = keyHex.toByteArray(Charsets.UTF_8)
            val iv = keyBytes.copyOfRange(0, 16)
            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(iv))
            val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
            return String(encrypted, Charsets.ISO_8859_1)
        }

        private fun doubleBase64(input: String): String {
            val first = Base64.getEncoder().encodeToString(input.toByteArray(Charsets.ISO_8859_1)).replace("=", "")
            return Base64.getEncoder().encodeToString(first.toByteArray()).replace("=", "")
        }
    }
}
