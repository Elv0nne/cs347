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

        // SỬA LỖI vòng 2 (xác nhận qua log thực tế mới nhất): bản CLAMP trước đó (trả
        // 206 với start bị kẹp về size-1) làm ExoPlayer LẶP VÔ HẠN thay vì crash: nó
        // gửi lại đúng request "Range: bytes=2222032263-" nhiều lần liên tiếp (có
        // backoff tăng dần: 0.13s -> 1.1s -> 2.1s...) mà không bao giờ tiến lên. Lý do:
        // response Content-Range trả về "bytes 206394888-206394888/206394889" không
        // khớp với start=2222032263 mà nó yêu cầu, nên ExoPlayer coi response là không
        // đáng tin và không cập nhật lại vị trí đọc nội bộ, cứ thế lặp lại request cũ.
        //
        // Quay lại trả 416 (đúng hành vi mà DefaultHttpDataSource/ProgressiveMediaPeriod
        // của ExoPlayer được thiết kế để xử lý khi Mp4Extractor scan-seek tìm moov atom
        // vượt quá cuối file thật): 416 kèm "Content-Range: bytes */<size>" là tín hiệu
        // chuẩn RFC 7233 để client biết ngay kích thước thật của resource và tự dừng
        // scan/lùi lại, thay vì nhận 206 với dữ liệu ở vị trí "lạ" rồi bị bối rối.
        if (start > endInclusive || start < 0) {
            Log.e(TAG, "intercept: THẤT BẠI - range không hợp lệ start=$start endInclusive=$endInclusive size=$size rangeHeader=$rangeHeader")
            return errorResponse(request, 416, "Range Not Satisfiable", extraHeaders = mapOf("Content-Range" to "bytes */$size"))
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

    private fun errorResponse(
        request: Request,
        code: Int,
        message: String,
        extraHeaders: Map<String, String> = emptyMap()
    ): Response {
        val builder = Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message(message)
            // SỬA LỖI: thêm "Content-Length: 0" tường minh. DefaultHttpDataSource của
            // ExoPlayer parse Content-Length khi mở connection; thiếu header này với
            // response 416/không có body có thể khiến nó không nhận diện đúng response
            // là "hoàn chỉnh, không có dữ liệu" trước khi đọc "Content-Range" để suy ra
            // kích thước thật, dẫn tới xử lý sai luồng lỗi 416 phía trên.
            .header("Content-Length", "0")
            .body("".toResponseBody(null))
        extraHeaders.forEach { (k, v) -> builder.header(k, v) }
        return builder.build()
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
            if (currentPos > endByteInclusive) {
                Log.d(TAG, "SegmentSource.read: đã đọc hết range (currentPos=$currentPos > endByteInclusive=$endByteInclusive), kết thúc stream")
                return -1L
            }

            if (currentBuffer.exhausted()) {
                val segIndex = (currentPos / FRAGMENT_SIZE).toInt()
                val segStart = segIndex.toLong() * FRAGMENT_SIZE
                val segmentBytes = fetchSegment(segIndex)
                if (segmentBytes.isEmpty()) {
                    Log.e(TAG, "SegmentSource.read: THẤT BẠI - fetchSegment(segIndex=$segIndex) trả về rỗng tại currentPos=$currentPos md5Id=$md5Id resId=$resId baseUrl=$baseUrl, dừng stream")
                    return -1L
                }
                val offsetInSeg = (currentPos - segStart).toInt().coerceIn(0, segmentBytes.size)
                currentBuffer.write(segmentBytes, offsetInSeg, segmentBytes.size - offsetInSeg)
            }

            val remaining = endByteInclusive - currentPos + 1
            val toRead = minOf(byteCount, remaining, currentBuffer.size)
            if (toRead <= 0) {
                Log.w(TAG, "SegmentSource.read: toRead<=0 (byteCount=$byteCount remaining=$remaining bufferSize=${currentBuffer.size}) tại currentPos=$currentPos, dừng stream")
                return -1L
            }
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
            Log.d(TAG, "fetchSegment: segIndex=$index md5Id=$md5Id resId=$resId totalSize=$totalSize url=$segUrl")
            val req = Request.Builder()
                .url(segUrl)
                .header("Referer", "https://abysscdn.com/")
                .build()
            val raw = runCatching {
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) {
                        Log.w(TAG, "fetchSegment: segIndex=$index -> HTTP ${resp.code} không thành công, url=$segUrl")
                        ByteArray(0)
                    } else {
                        val bytes = resp.body?.bytes() ?: ByteArray(0)
                        Log.d(TAG, "fetchSegment: segIndex=$index THÀNH CÔNG, nhận ${bytes.size} byte")
                        bytes
                    }
                }
            }.onFailure { e ->
                Log.w(TAG, "fetchSegment: segIndex=$index EXCEPTION khi tải segment (url=$segUrl): ${e.message}")
            }.getOrDefault(ByteArray(0))

            // SỬA LỖI (xác nhận qua phân tích file thật tải bằng abyss-dl.jar): ngay
            // sau khi box "moov" kết thúc, 8 byte header của box "mdat" tiếp theo BỊ
            // HỎNG ở nguồn Abyss/CDN (size field đọc ra rác dạng ~2 tỷ, type field
            // không phải "mdat"). Vì tổng độ dài file (totalSize) đã biết trước và
            // "mdat" luôn kéo dài từ ngay sau nó tới hết file, ta có thể tự tính lại
            // size đúng = totalSize - offsetOfMdatHeader và ghi đè 8 byte header đó
            // NGAY KHI segment 0 vừa tải về — chỉ chạy đúng 1 lần trên segment chứa
            // ranh giới moov->mdat, không đụng tới byte dữ liệu media nào khác.
            if (index == 0) {
                patchCorruptMdatHeaderIfNeeded(raw)
            }
            return raw
        }

        /**
         * Dò box top-level "moov" bắt đầu ngay sau "ftyp" ở đầu segment 0, tính vị trí
         * kết thúc của nó (= vị trí box "mdat" phải bắt đầu), rồi kiểm tra 8 byte tại đó:
         * nếu type field KHÔNG phải "mdat" hợp lệ (dấu hiệu hỏng), ghi đè lại đúng
         * [size 32-bit][mdat] với size = totalSize - offset. Sửa in-place trên mảng byte
         * truyền vào (an toàn vì ByteArray là mutable, không cần copy).
         */
        private fun patchCorruptMdatHeaderIfNeeded(seg0: ByteArray) {
            if (seg0.size < 32) return
            try {
                // ftyp phải nằm ở offset 0
                val ftypSize = readUInt32BE(seg0, 0)
                val ftypType = String(seg0, 4, 4, Charsets.US_ASCII)
                if (ftypType != "ftyp" || ftypSize <= 0 || ftypSize.toInt() + 8 > seg0.size) return

                val moovOffset = ftypSize.toInt()
                val moovSize = readUInt32BE(seg0, moovOffset)
                val moovType = String(seg0, moovOffset + 4, 4, Charsets.US_ASCII)
                if (moovType != "moov" || moovSize <= 0) return

                val mdatHeaderOffset = moovOffset + moovSize.toInt()
                if (mdatHeaderOffset + 8 > seg0.size) {
                    Log.d(TAG, "patchCorruptMdatHeaderIfNeeded: mdat header offset=$mdatHeaderOffset vượt quá segment 0 (size=${seg0.size}), bỏ qua (sẽ nằm ở segment sau)")
                    return
                }

                val currentType = String(seg0, mdatHeaderOffset + 4, 4, Charsets.US_ASCII)
                if (currentType == "mdat") {
                    Log.d(TAG, "patchCorruptMdatHeaderIfNeeded: mdat header tại offset=$mdatHeaderOffset đã hợp lệ, không cần vá")
                    return
                }

                val correctMdatSize = totalSize - mdatHeaderOffset
                if (correctMdatSize <= 8 || correctMdatSize > 0xFFFFFFFFL) {
                    Log.w(TAG, "patchCorruptMdatHeaderIfNeeded: correctMdatSize=$correctMdatSize không hợp lệ (offset=$mdatHeaderOffset totalSize=$totalSize), bỏ qua vá")
                    return
                }

                Log.w(TAG, "patchCorruptMdatHeaderIfNeeded: PHÁT HIỆN mdat header HỎNG tại offset=$mdatHeaderOffset (type đọc được='$currentType') -> VÁ LẠI size=$correctMdatSize type='mdat'")

                writeUInt32BE(seg0, mdatHeaderOffset, correctMdatSize)
                seg0[mdatHeaderOffset + 4] = 'm'.code.toByte()
                seg0[mdatHeaderOffset + 5] = 'd'.code.toByte()
                seg0[mdatHeaderOffset + 6] = 'a'.code.toByte()
                seg0[mdatHeaderOffset + 7] = 't'.code.toByte()
            } catch (e: Exception) {
                Log.w(TAG, "patchCorruptMdatHeaderIfNeeded: EXCEPTION khi vá mdat header: ${e.message}")
            }
        }

        private fun readUInt32BE(data: ByteArray, offset: Int): Long {
            return ((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF)
        }

        private fun writeUInt32BE(data: ByteArray, offset: Int, value: Long) {
            data[offset] = ((value shr 24) and 0xFF).toByte()
            data[offset + 1] = ((value shr 16) and 0xFF).toByte()
            data[offset + 2] = ((value shr 8) and 0xFF).toByte()
            data[offset + 3] = (value and 0xFF).toByte()
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
