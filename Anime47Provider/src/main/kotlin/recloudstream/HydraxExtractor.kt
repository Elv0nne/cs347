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

    // HIỆU NĂNG: Log.d/Log.w/Log.e của Android vẫn build chuỗi thông điệp (string
    // interpolation, hàng chục field mỗi dòng) TRƯỚC KHI kiểm tra xem log có thực sự
    // được ghi hay không — chi phí CPU đó tồn tại ngay cả trên build release khi log
    // debug bị lọc ở tầng logger. Trên các hot path chạy MỖI segment/MỖI request
    // (fetchSegment, SegmentSource.read, HydraxInterceptor.intercept) tần suất gọi có
    // thể lên tới hàng trăm lần mỗi phút khi phát 1 video — dùng logD/logW với lambda
    // "message: () -> String" để chuỗi chỉ được build khi Log.isLoggable(TAG, level)
    // trả về true (mặc định false cho VERBOSE/DEBUG trên thiết bị người dùng thật,
    // chỉ true khi bật `adb shell setprop log.tag.<TAG> DEBUG` để debug thủ công).
    private inline fun logD(tag: String, message: () -> String) {
        if (Log.isLoggable(tag, Log.DEBUG)) Log.d(tag, message())
    }

    private inline fun logW(tag: String, message: () -> String) {
        if (Log.isLoggable(tag, Log.WARN)) Log.w(tag, message())
    }
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
        logD(TAG) { "isHydraxUrl: url=$url host=$host -> $result" }
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
            logD(TAG) { "getVideoId: không parse được host của url=$url, fallback trả về chính url" }
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
        logD(TAG) { "getVideoId: url=$url host=$host -> videoId=$result" }
        return result
    }

    private suspend fun fetchMp4Metadata(videoId: String, referer: String): Mp4Data? {
        // ĐỔI LẠI: abysscdn.com (domain gốc) dùng dạng query "?v=videoId", khác với
        // dạng path "/videoId" của abyssplayer.com — xem ghi chú tại ABYSS_BASE_URL.
        val embedUrl = "$ABYSS_BASE_URL/?v=$videoId"
        logD(TAG) { "fetchMp4Metadata: videoId=$videoId embedUrl=$embedUrl referer=$referer" }

        val response = app.get(
            embedUrl,
            headers = mapOf(
                "Referer" to referer,
                "User-Agent" to "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
            ),
            interceptor = cloudflareKiller,
            timeout = 15000
        )
        logD(TAG) { "fetchMp4Metadata: HTTP code=${response.code} successful=${response.isSuccessful}" }
        val html = response.text
        logD(TAG) { "fetchMp4Metadata: HTML embed dài ${html.length} ký tự" }

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
        logD(TAG) { "fetchMp4Metadata: tìm thấy 'datas' (base64, dài ${encodedDatas.length} ký tự)" }

        val decodedJson = String(Base64.getDecoder().decode(encodedDatas), Charsets.ISO_8859_1)
        logD(TAG) { "fetchMp4Metadata: base64-decode datas OK, JSON dài ${decodedJson.length} ký tự" }
        val datas = mapper.readValue(decodedJson, Datas::class.java)
        logD(TAG) { "fetchMp4Metadata: parse Datas OK -> md5_id=${datas.md5_id} slug=${datas.slug} user_id=${datas.user_id} media_len=${datas.media?.length}" }
        val encryptedMedia = datas.media
        if (encryptedMedia == null) {
            Log.e(TAG, "fetchMp4Metadata: THẤT BẠI - field 'media' rỗng/null trong datas đã parse")
            return null
        }

        val mediaKey = keyForString("${datas.user_id}:${datas.slug}:${datas.md5_id}")
        val decryptedJson = aesCtrDecryptFromIso(encryptedMedia, mediaKey)
        logD(TAG) { "fetchMp4Metadata: giải mã AES-CTR OK, JSON video dài ${decryptedJson.length} ký tự" }
        val video = mapper.readValue(decryptedJson, VideoData::class.java)

        val result = video.mp4?.copy(slug = datas.slug, md5_id = datas.md5_id)
        if (result == null) {
            Log.e(TAG, "fetchMp4Metadata: THẤT BẠI - field 'mp4' rỗng/null sau khi parse VideoData")
        } else {
            logD(TAG) { "fetchMp4Metadata: THÀNH CÔNG -> domains=${result.domains} sources_count=${result.sources?.size} md5_id=${result.md5_id}" }
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
        logD(TAG) { "getLinks: BẮT ĐẦU streamUrl=$streamUrl providerName=$providerName serverName=$serverName referer=$referer" }

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
        logD(TAG) { "getLinks: md5Id=$md5Id domain=$domain, tổng ${sources.size} sources thô" }
        if (sources.isEmpty()) {
            logW(TAG) { "getLinks: mp4.sources rỗng hoặc toàn null -> sẽ không có link nào được trả về" }
        }

        val displayBaseName = serverName?.takeIf { it.isNotBlank() } ?: "$providerName HY"

        val links = sources.mapIndexedNotNull { index, source ->
            val sub = source.sub
            val size = source.size
            val resId = source.res_id
            if (sub == null || size == null || resId == null) {
                logW(TAG) { "getLinks: bỏ qua source[$index] thiếu field bắt buộc -> sub=$sub size=$size resId=$resId label=${source.label}" }
                return@mapIndexedNotNull null
            }
            val baseUrl = "https://$sub.${domain.substringAfter(".")}"
            val relayUrl = buildRelayUrl(baseUrl, md5Id, resId, size)
            val quality = source.label?.filter { it.isDigit() }?.toIntOrNull() ?: Qualities.Unknown.value
            logD(TAG) { "getLinks: source[$index] label=${source.label} quality=$quality baseUrl=$baseUrl relayUrl=$relayUrl size=$size" }

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

        logD(TAG) { "getLinks: KẾT THÚC - trả về ${links.size}/${sources.size} link hợp lệ cho videoId=$videoId" }
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

    // HIỆU NĂNG (lỗi nghiêm trọng nhất tìm được trong toàn bộ plugin): OkHttpClient()
    // mặc định KHÔNG đặt timeout riêng (connect/read/write mặc định 10s của OkHttp là
    // ổn, nhưng quan trọng hơn: mỗi lần "OkHttpClient()" được new lên, nó tạo hẳn 1
    // connection pool + dispatcher/thread pool RIÊNG, không tái sử dụng kết nối TCP/TLS
    // đã có với CDN Abyss cho các segment TRƯỚC ĐÓ của CÙNG 1 video). Trước đây field
    // này đã là "val" cấp object (tốt, chỉ tạo 1 lần cho toàn bộ interceptor) — giữ
    // nguyên đó, nhưng bổ sung timeout tường minh: ExoPlayer có thể mở hàng chục Range
    // request trong lúc buffer/seek; nếu 1 CDN segment bị treo (không đóng socket,
    // không trả lỗi) mà không có timeout, connection đó chiếm giữ mãi 1 thread trong
    // OkHttp dispatcher, dồn lại có thể làm cạn pool và khiến CÁC segment khác (kể cả
    // của video khác đang xem) cũng bị chặn theo dây chuyền.
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(20, java.util.concurrent.TimeUnit.SECONDS)
        .writeTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
        .build()

    // SỬA LỖI HIỆU NĂNG NGHIÊM TRỌNG NHẤT trong toàn bộ plugin: trước đây
    // SegmentSource.init { detectCorrectTotalSize(...) } chạy MỖI LẦN 1 SegmentSource
    // mới được tạo — tức là MỖI Range request mới mà ExoPlayer gửi tới relay host
    // (thường xảy ra rất nhiều lần trong 1 lần xem phim: mở luồng ban đầu, mọi lần
    // seek, mọi lần player mở lại kết nối sau khi buffer đầy rồi rỗng lại...). Hàm này
    // tự thực hiện 1 HTTP GET ĐỒNG BỘ tải lại TOÀN BỘ segment 0 (tối đa 2MB) chỉvđể dò
    // xem totalSize khai báo có đúng hay không. Kết quả: với 1 video dài, có thể tải
    // lại segment 0 (2MB) hàng chục lần một cách vô ích — vừa tốn băng thông gấp nhiều
    // lần cần thiết, vừa cộng thêm độ trễ mạng thật (1 round-trip + tải 2MB) vào MỌI
    // request Range, kể cả những request giữa phim không hề liên quan tới segment 0.
    // Sửa: cache kết quả theo key (baseUrl, md5Id, resId, declaredTotalSize) — bất biến
    // cho cùng 1 video/nguồn trong suốt phiên phát, nên chỉ cần dò đúng 1 LẦN DUY NHẤT
    // cho lần Range request đầu tiên; mọi request tiếp theo (kể cả sau khi seek) dùng
    // lại kết quả đã cache, không gọi mạng thêm lần nào nữa.
    private val totalSizeCorrectionCache =
        java.util.concurrent.ConcurrentHashMap<String, Long?>()

    // HIỆU NĂNG: cache nhỏ, bounded, cho các segment 2MB đã tải — xem ghi chú đầy đủ
    // tại điểm dùng trong SegmentSource.fetchSegment(). Giới hạn số lượng segment giữ
    // lại (không phải giới hạn theo byte) để đơn giản và đủ tốt: ExoPlayer thường chỉ
    // seek qua lại trong phạm vi vài segment gần vị trí hiện tại, không cần cache cả
    // video (sẽ tốn RAM không cần thiết, đặc biệt với video dài nhiều tiếng).
    // LinkedHashMap với accessOrder=true tự động đưa entry vừa dùng lên cuối, removeEldestEntry
    // tự xoá entry cũ nhất khi vượt quá SEGMENT_CACHE_MAX_ENTRIES — cho hành vi LRU chuẩn
    // mà không cần tự triển khai logic đếm/xoá thủ công. Bọc synchronized vì
    // LinkedHashMap không thread-safe và nhiều Range request có thể đọc/ghi đồng thời
    // từ các thread khác nhau của OkHttp dispatcher đang phục vụ ExoPlayer.
    private const val SEGMENT_CACHE_MAX_ENTRIES = 4
    private val segmentByteCache = object : LinkedHashMap<String, ByteArray>(
        SEGMENT_CACHE_MAX_ENTRIES, 0.75f, true
    ) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, ByteArray>?): Boolean {
            return size > SEGMENT_CACHE_MAX_ENTRIES
        }
    }

    // Xem ghi chú logD/logW ở HydraxExtractor — áp dụng cùng nguyên tắc cho
    // HydraxInterceptor vì SegmentSource.read()/fetchSegment() là hot path chạy mỗi
    // 2MB segment tải về, tần suất cao hơn hẳn các hàm one-shot khác trong file.
    private inline fun logD(tag: String, message: () -> String) {
        if (Log.isLoggable(tag, Log.DEBUG)) Log.d(tag, message())
    }

    private inline fun logW(tag: String, message: () -> String) {
        if (Log.isLoggable(tag, Log.WARN)) Log.w(tag, message())
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

        logD(TAG) { "intercept: relay request rangeHeader=${request.header("Range")} base=$baseUrl md5=$md5Id res=$resId size=$size" }

        if (baseUrl == null || md5Id == null || resId == null || size == null) {
            Log.e(TAG, "intercept: THẤT BẠI - thiếu tham số relay bắt buộc (base/md5/res/size), url=${request.url}")
            return errorResponse(request, 500, "Missing relay parameters")
        }

        // SỬA LỖI GỐC RỄ (bug mới phát hiện qua log thực tế: start=1795315897 vượt xa
        // size=169987160 khai báo, không phải lệch nhỏ do khối moov như trước): trước
        // đây interceptor VALIDATE Range dựa theo "size" (totalSize) NGUYÊN GỐC từ
        // metadata NGAY TẠI ĐÂY, rồi CHỈ SAU ĐÓ mới tạo SegmentSource — và chính
        // SegmentSource mới là nơi tự dò + sửa lại totalSize thật (detectCorrectTotalSize).
        // Hệ quả: nếu totalSize thật LỚN HƠN NHIỀU so với "size" khai báo (không chỉ
        // lệch đúng bằng độ dài 1 khối "moov" bị lặp, mà lệch cả trăm/nghìn lần), thì
        // NGAY LẦN REQUEST ĐẦU TIÊN nhận response 206 với Content-Range trả về totalSize
        // ĐÃ SỬA (lớn hơn) — nhưng URL relay mà ExoPlayer dùng để tạo request Range TIẾP
        // THEO vẫn giữ nguyên "size" cũ (URL relay được build 1 lần, không tự cập nhật).
        // ExoPlayer thấy resource thật dài hơn (qua Content-Range trước đó) nên seek tới
        // 1 vị trí start hợp lệ với totalSize ĐÃ SỬA nhưng lại KHÔNG hợp lệ với "size" cũ
        // trong URL -> validate ở đây luôn thất bại (416) dù thực ra start hoàn toàn hợp
        // lệ với totalSize thật. Vì validate diễn ra TRƯỚC khi SegmentSource kịp sửa lại
        // totalSize, video không bao giờ thoát khỏi vòng lặp lỗi này.
        //
        // Cách sửa: dò/tra cache totalSize THẬT ngay tại đây, TRƯỚC khi parse & validate
        // Range — dùng chung "totalSizeCorrectionCache" (đã có sẵn, key theo
        // baseUrl|md5Id|resId|declaredSize) nên chỉ tốn 1 lần dò mạng cho toàn bộ phiên
        // phát, y hệt cơ chế cache cũ, không thêm chi phí học ngoài lần đầu.
        val cacheKey = "$baseUrl|$md5Id|$resId|$size"
        val correctedSize = totalSizeCorrectionCache.computeIfAbsent(cacheKey) {
            detectCorrectTotalSize(baseUrl, md5Id, resId, size)
        }
        val effectiveSize = correctedSize ?: size
        if (correctedSize != null && correctedSize != size) {
            logW(TAG) { "intercept: PHÁT HIỆN size khai báo SAI (declared=$size) -> size THẬT=$correctedSize (chênh lệch=${correctedSize - size})" }
        }

        val rangeHeader = request.header("Range")
        val (start, endInclusive) = parseRange(rangeHeader, effectiveSize)

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
        //
        // Quan trọng: dùng effectiveSize (đã sửa) ở đây, KHÔNG dùng size gốc — nếu không
        // start hợp lệ với totalSize thật vẫn có thể bị từ chối oan như bug gốc.
        if (start > endInclusive || start < 0) {
            val overshootRatio = if (effectiveSize > 0) start.toDouble() / effectiveSize.toDouble() else -1.0

            // SỬA LỖI vòng 3 (freeze/kẹt buffer xác nhận qua thực tế, không phải infinite
            // retry loop như vòng 2): khi overshoot RẤT LỚN (vd >2 lần effectiveSize),
            // Range này gần như chắc chắn là request "mồ côi" từ 1 DataSource CŨ (video/tập
            // trước) mà ExoPlayer chưa kịp release/reset, bị gửi nhầm sang relay URL hiện
            // tại. Trả 416 cứng ở đây khiến DefaultHttpDataSource coi lỗi này KHÔNG thể
            // phục hồi (khác với case moov-scan-overshoot nhỏ mà ExoPlayer biết tự lùi lại
            // — case đó vẫn giữ nguyên hành vi 416 cũ ở nhánh else bên dưới), nên toàn bộ
            // player bị treo/đứng buffer vĩnh viễn thay vì tự mở lại đúng request cho video
            // hiện tại.
            //
            // Không lặp lại lỗi "clamp 206 sai" của vòng 2 (start giữ nguyên giá trị KHÔNG
            // hợp lệ trong Content-Range khiến player thấy phản hồi "không khớp" rồi lặp
            // request cũ): ở đây ta clamp CẢ start LẪN end về 1 cửa sổ nhỏ HỢP LỆ ở cuối
            // file (đúng với effectiveSize hiện tại), tức là trả lời "đây là dữ liệu thật,
            // hợp lệ, ở gần cuối file" thay vì "đây là lỗi". DefaultHttpDataSource nhận
            // Content-Range khớp với response thật (không lệch như vòng 2) nên cập nhật lại
            // đúng vị trí đọc, thoát khỏi vòng lặp/treo và tự seek lại chỗ cần thiết cho
            // đúng bằng metadata (moov) mà nó vừa đọc được.
            val staleSessionThreshold = 2.0
            if (overshootRatio > staleSessionThreshold) {
                val clampedEnd = effectiveSize - 1
                val clampedStart = maxOf(0L, clampedEnd - FRAGMENT_SIZE + 1)
                logW(TAG) {
                    "intercept: Range MỒ CÔI phát hiện (start=$start overshootRatio=$overshootRatio " +
                        "effectiveSize=$effectiveSize declaredSize=$size rangeHeader=$rangeHeader) -> " +
                        "khả năng cao là request sót lại từ phiên phát/video TRƯỚC ĐÓ. " +
                        "KHÔNG trả 416 cứng (từng gây treo/đứng buffer) -> clamp về cửa sổ hợp lệ " +
                        "cuối file [$clampedStart-$clampedEnd] để player nhận dữ liệu thật, tự đồng " +
                        "bộ lại vị trí đọc và phục hồi."
                }
                val segmentSource = SegmentSource(client, baseUrl, md5Id, resId, effectiveSize, clampedStart, clampedEnd)
                val contentLength = clampedEnd - clampedStart + 1
                val body: ResponseBody = segmentSource.buffer()
                    .let { buffered -> object : ResponseBody() {
                        override fun contentType() = "video/mp4".toMediaTypeOrNull()
                        override fun contentLength() = contentLength
                        override fun source() = buffered
                    } }
                return Response.Builder()
                    .request(request)
                    .protocol(Protocol.HTTP_1_1)
                    .code(206).message("Partial Content")
                    .header("Accept-Ranges", "bytes")
                    .header("Content-Length", contentLength.toString())
                    .header("Content-Range", "bytes $clampedStart-$clampedEnd/$effectiveSize")
                    .body(body)
                    .build()
            }

            // Overshoot nhỏ (vd do lệch totalSize/moov-scan còn sót lại) — giữ nguyên hành
            // vi 416 gốc, ExoPlayer đã được xác nhận tự xử lý tốt case này (xem ghi chú
            // "vòng 2" phía trên).
            Log.e(TAG, "intercept: THẤT BẠI - range không hợp lệ start=$start endInclusive=$endInclusive effectiveSize=$effectiveSize declaredSize=$size rangeHeader=$rangeHeader overshootRatio=$overshootRatio")
            return errorResponse(request, 416, "Range Not Satisfiable", extraHeaders = mapOf("Content-Range" to "bytes */$effectiveSize"))
        }

        val segmentSource = SegmentSource(client, baseUrl, md5Id, resId, effectiveSize, start, endInclusive)
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
                .header("Content-Range", "bytes $start-$endInclusive/$effectiveSize")
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

    /**
     * Tải segment 0 (chứa ftyp+moov, không phụ thuộc totalSize để giải mã vì baseUrl/
     * md5Id/resId là cố định) bằng totalSize khai báo, quét tìm "mdat" thật trong đó,
     * và trả về totalSize đã sửa. Trả về null nếu không tìm thấy dấu hiệu sai lệch
     * (file bình thường, không cần sửa) hoặc nếu việc dò gặp lỗi bất kỳ — trong mọi
     * trường hợp không chắc chắn, giữ nguyên totalSize gốc để không phá vỡ video vốn
     * đã đúng.
     *
     * ĐÃ CHUYỂN từ SegmentSource lên cấp object: cần gọi được từ intercept() TRƯỚC KHI
     * validate Range (xem ghi chú tại điểm gọi trong intercept()), chứ không chỉ từ
     * bên trong SegmentSource sau khi Range đã (có thể bị từ chối oan) validate xong.
     */
    private fun detectCorrectTotalSize(
        baseUrl: String,
        md5Id: Int,
        resId: Int,
        declaredTotalSize: Long
    ): Long? {
        return try {
            val probePath = "/mp4/$md5Id/$resId/$declaredTotalSize/$FRAGMENT_SIZE/0"
            val probeToken = tokenFor(probePath, declaredTotalSize)
            val probeUrl = "$baseUrl/sora/$declaredTotalSize/$probeToken"
            val req = Request.Builder()
                .url(probeUrl)
                .header("Referer", "https://abysscdn.com/")
                .build()
            val seg0 = client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                resp.body?.bytes() ?: return null
            }
            if (seg0.size < 32) return null

            val ftypSize = readUInt32BE(seg0, 0)
            val ftypType = String(seg0, 4, 4, Charsets.US_ASCII)
            if (ftypType != "ftyp" || ftypSize <= 0) return null

            // SỬA LỖI (bug thứ 2 tái phát y hệt lần trước — cùng gốc "mdat/moov lệch",
            // xác nhận qua log thực tế: realTotalSize bị thổi phồng gấp ~10.5 lần size
            // khai báo, quá lớn để là lỗi "1 khối moov lặp" thật như lần đầu): thuật
            // toán CŨ quét MÙ từng byte tìm chữ ký "mdat" trong TOÀN BỘ phần còn lại của
            // buffer (kể cả bên trong nội dung box "moov" chưa được bỏ qua đúng cách) —
            // dữ liệu nhị phân bên trong moov (bảng sample, metadata nén, thumbnail
            // nhúng...) HOÀN TOÀN CÓ THỂ tình cờ chứa đúng 4 byte 'm','d','a','t' liền
            // nhau ở 1 vị trí không phải box header thật. Khi khớp nhầm, 4 byte NGAY
            // TRƯỚC đó bị đọc nhầm thành "kích thước mdat" dù thực ra là dữ liệu ngẫu
            // nhiên khác — cộng với offset đó cho ra 1 "realTotalSize" hoàn toàn vô
            // nghĩa (có thể lớn gấp nhiều lần file thật), sinh ra bug 416 y hệt vòng 1.
            //
            // Sửa: PARSE ĐÚNG cấu trúc box MP4 (size + type tuần tự tại top-level, nhảy
            // đúng offset += size mỗi vòng) thay vì quét byte mù — bỏ qua toàn bộ box
            // "moov" (và bất kỳ box nào khác không phải "mdat") theo ĐÚNG kích thước
            // khai báo trong header của chính nó, chỉ dừng lại và tin tưởng khi gặp
            // "mdat" ở ĐÚNG vị trí bắt đầu 1 box top-level — không còn khả năng khớp
            // nhầm dữ liệu bên trong 1 box khác.
            var offset = ftypSize.toInt()
            var mdatHeaderOffset = -1
            var mdatDeclaredSize = -1L
            while (offset + 8 <= seg0.size) {
                val boxSize32 = readUInt32BE(seg0, offset)
                val boxType = String(seg0, offset + 4, 4, Charsets.US_ASCII)

                if (boxType == "mdat") {
                    mdatHeaderOffset = offset
                    mdatDeclaredSize = boxSize32
                    break
                }

                // box size == 0 nghĩa là "kéo dài tới hết file" (hiếm, thường chỉ dùng
                // cho box cuối cùng) — không có "size" cố định để nhảy tiếp, dừng quét
                // an toàn thay vì đoán mò.
                if (boxSize32 <= 0) {
                    logD(TAG) { "detectCorrectTotalSize: gặp box '$boxType' size=0/không hợp lệ tại offset=$offset, dừng quét an toàn" }
                    break
                }
                // box size == 1 nghĩa là size thật nằm ở 8 byte tiếp theo (64-bit
                // "largesize") — vượt phạm vi buffer 2MB một cách bất thường ở segment 0,
                // không tin cậy để tiếp tục quét, dừng an toàn.
                if (boxSize32 == 1L) {
                    logD(TAG) { "detectCorrectTotalSize: box '$boxType' dùng largesize 64-bit tại offset=$offset, không hỗ trợ, dừng quét an toàn" }
                    break
                }

                offset += boxSize32.toInt()
            }

            if (mdatHeaderOffset < 0 || mdatDeclaredSize <= 8) {
                logD(TAG) { "detectCorrectTotalSize: không tìm thấy box 'mdat' hợp lệ ở top-level trong segment 0 (có thể mdat nằm ở segment sau, hoặc file không cần sửa)" }
                return null
            }
            val mdatSize = mdatDeclaredSize

            val realTotalSize = mdatHeaderOffset + mdatSize
            if (realTotalSize == declaredTotalSize) {
                // Đã đúng sẵn, không cần sửa gì.
                return null
            }
            if (realTotalSize < declaredTotalSize) {
                // Nhỏ hơn kích thước khai báo là bất thường/không tin cậy bằng trường hợp
                // "thiếu đuôi" (lớn hơn) mà ta đã xác nhận qua thực nghiệm; bỏ qua để an toàn.
                logW(TAG) { "detectCorrectTotalSize: realTotalSize=$realTotalSize < declared=$declaredTotalSize, bất thường -> bỏ qua, giữ nguyên" }
                return null
            }

            // SANITY CHECK cuối (lớp phòng vệ thứ 2, độc lập với việc parse box đã sửa
            // ở trên): độ lệch thật giữa "size" khai báo và totalSize thật, theo mọi
            // trường hợp đã quan sát được (khối "moov" bị lặp/chèn nhầm), chỉ nằm trong
            // khoảng vài trăm byte tới vài chục KB — KHÔNG BAO GIỜ lớn tới mức nhân đôi
            // hay nhân 10 lần kích thước file. Nếu chênh lệch vượt xa mọi giá trị hợp lý
            // (ví dụ do 1 edge-case parse box nào đó ở trên chưa lường hết), tốt hơn là
            // KHÔNG tin kết quả và giữ nguyên totalSize gốc, thay vì áp dụng 1 con số có
            // thể sai lệch nghiêm trọng hơn cả lỗi ban đầu.
            val maxPlausibleExtraBytes = 1_000_000L // 1 MB dư ra là đã rất rộng rãi so với thực tế quan sát được
            if (realTotalSize - declaredTotalSize > maxPlausibleExtraBytes) {
                logW(TAG) { "detectCorrectTotalSize: realTotalSize=$realTotalSize CHÊNH LỆCH BẤT THƯỜNG so với declared=$declaredTotalSize (vượt ngưỡng hợp lý $maxPlausibleExtraBytes byte) -> khả năng cao do khớp nhầm/parse sai, bỏ qua để an toàn, giữ nguyên totalSize gốc" }
                return null
            }
            realTotalSize
        } catch (e: Exception) {
            logW(TAG) { "detectCorrectTotalSize: EXCEPTION, giữ nguyên totalSize gốc: ${e.message}" }
            null
        }
    }

    private fun readUInt32BE(data: ByteArray, offset: Int): Long {
        return ((data[offset].toLong() and 0xFF) shl 24) or
            ((data[offset + 1].toLong() and 0xFF) shl 16) or
            ((data[offset + 2].toLong() and 0xFF) shl 8) or
            (data[offset + 3].toLong() and 0xFF)
    }

    private fun tokenFor(path: String, sizeForKey: Long): String {
        val key = md5HexOfDigits(sizeForKey)
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
        totalSizeFromMetadata: Long,
        startByte: Long,
        endByteInclusiveFromRequest: Long
    ) : Source {

        // SỬA LỖI GỐC RỄ (xác nhận qua phân tích byte-for-byte của file thật, so khớp
        // với 2 lần tải độc lập bằng 2 công cụ khác nhau): trường "size" mà Abyss trả
        // về trong metadata JSON (dùng làm totalSize cho relay/token) đôi khi NHỎ HƠN
        // kích thước file thật trên server của họ, đúng bằng độ dài của khối metadata
        // "moov" bị họ lặp lại/chèn nhầm 2 lần trong quá trình re-mux. Vì totalSize sai
        // được dùng làm KEY MÃ HÓA cho mọi token segment (kể cả segment 0), nó khiến
        // segment cuối cùng bị cắt cụt thiếu đúng phần đuôi "mdat" tương ứng — video
        // dừng đột ngột / ExoPlayer seek lố tay tới vị trí không tồn tại.
        //
        // SỬA LỖI (vòng 3): việc dò + sửa totalSize (detectCorrectTotalSize) đã được
        // CHUYỂN LÊN intercept() để chạy TRƯỚC KHI validate Range (xem ghi chú đầy đủ ở
        // đó) — nếu không, request Range hợp lệ với totalSize thật vẫn có thể bị 416 oan
        // vì validate cũ chạy trước khi SegmentSource kịp sửa lại totalSize. Do đó
        // "totalSizeFromMetadata"/"endByteInclusiveFromRequest" nhận vào đây ĐÃ LÀ giá
        // trị đúng (effectiveSize) do intercept() truyền xuống — không cần dò lại lần
        // nữa ở đây, tránh gọi mạng trùng lặp.
        private val totalSize: Long = totalSizeFromMetadata
        private val endByteInclusive: Long = endByteInclusiveFromRequest

        private var currentPos = startByte
        private val currentBuffer = Buffer()

        override fun read(sink: Buffer, byteCount: Long): Long {
            if (currentPos > endByteInclusive) {
                logD(TAG) { "SegmentSource.read: đã đọc hết range (currentPos=$currentPos > endByteInclusive=$endByteInclusive), kết thúc stream" }
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
                logW(TAG) { "SegmentSource.read: toRead<=0 (byteCount=$byteCount remaining=$remaining bufferSize=${currentBuffer.size}) tại currentPos=$currentPos, dừng stream" }
                return -1L
            }
            val read = currentBuffer.read(sink, toRead)
            if (read > 0) currentPos += read
            return read
        }

        override fun timeout(): Timeout = Timeout.NONE
        override fun close() {}

        private fun fetchSegment(index: Int): ByteArray {
            // HIỆU NĂNG: SegmentSource CŨ chỉ giữ 1 buffer cho segment ĐANG đọc — mỗi khi
            // ExoPlayer đóng connection hiện tại và mở 1 SegmentSource MỚI (Range request
            // mới), dù request mới trỏ vào ĐÚNG segment index vừa tải trước đó (rất phổ
            // biến: seek lùi/tiến trong cùng cửa sổ 2MB, hoặc ExoPlayer huỷ + mở lại
            // connection khi buffer đầy rồi cạn), segment 2MB đó bị tải lại HOÀN TOÀN từ
            // mạng. Tra cache dùng chung cấp HydraxInterceptor trước (key gồm đủ
            // baseUrl+md5Id+resId+totalSize+segIndex để không đụng giữa các video/nguồn
            // khác nhau) — chỉ gọi mạng khi thực sự chưa có trong cache.
            val cacheKey = "$baseUrl|$md5Id|$resId|$totalSize|$index"
            val cachedBytes = synchronized(segmentByteCache) { segmentByteCache[cacheKey] }
            if (cachedBytes != null) {
                logD(TAG) { "fetchSegment: segIndex=$index CACHE HIT, dùng lại ${cachedBytes.size} byte đã tải trước đó (không gọi mạng)" }
                return cachedBytes
            }

            val path = "/mp4/$md5Id/$resId/$totalSize/$FRAGMENT_SIZE/$index"
            val token = HydraxInterceptor.tokenFor(path, totalSize)
            val segUrl = "$baseUrl/sora/$totalSize/$token"
            logD(TAG) { "fetchSegment: segIndex=$index md5Id=$md5Id resId=$resId totalSize=$totalSize url=$segUrl" }
            val req = Request.Builder()
                .url(segUrl)
                .header("Referer", "https://abysscdn.com/")
                .build()

            // SỬA LỖI GỐC RỄ (cache-poisoning bởi segment bị cắt cụt): trước đây bytes
            // tải về CHỈ cần "không rỗng" (bytes.isNotEmpty()) là được lưu VĨNH VIỄN vào
            // segmentByteCache dùng chung cho cả phiên phát. Nếu 1 lần tải bị trục trặc
            // mạng giữa chừng (CDN đóng kết nối sớm, đứt gói...) và chỉ nhận được VD.
            // 64KB thay vì đủ kích thước segment thật (2MiB, hoặc phần đuôi ngắn hơn cho
            // segment cuối), đoạn dữ liệu CỤT đó vẫn được coi là hợp lệ và bị cache lại
            // — mọi Range request sau này (kể cả sau khi seek) trong SUỐT phần đời còn
            // lại của cache entry đó đều đọc lại đúng bản CỤT này, làm lệch toàn bộ phép
            // tính offset phía sau -> nội dung file (đặc biệt nếu rơi vào vùng 'moov')
            // bị hỏng, có thể sinh ra các giá trị vô nghĩa (vd. bảng chunk-offset trỏ
            // tới byte cách xa thực tế cả GB) mà ExoPlayer sau đó cố seek tới, gây đúng
            // lỗi "Range không hợp lệ, overshootRatio quá lớn" quan sát được qua logcat.
            //
            // Sửa: tính trước độ dài ĐÚNG kỳ vọng của segment này (2MiB, trừ khi đây là
            // segment CUỐI thì ngắn hơn theo phần dư thật của totalSize) và CHỈ cache +
            // trả về bytes khi độ dài khớp chính xác. Nếu lệch, coi như tải thất bại
            // (trả rỗng) — SegmentSource.read() đã có sẵn logic dừng stream an toàn cho
            // trường hợp fetchSegment() trả rỗng, tốt hơn nhiều so với âm thầm phát tán
            // dữ liệu cụt đi khắp phiên phát.
            val segStart = index.toLong() * FRAGMENT_SIZE
            val expectedLen = minOf(FRAGMENT_SIZE, totalSize - segStart)

            // Cho phép 1 lần thử lại: giờ 1 lần tải bị cắt cụt do trục trặc mạng thoáng
            // qua sẽ bị từ chối (không cache) thay vì âm thầm phát tán dữ liệu hỏng —
            // nhưng nếu không thử lại, chỉ 1 lần chập chờn mạng cũng đủ làm dừng hẳn cả
            // luồng phát (SegmentSource.read() trả -1 ngay khi fetchSegment rỗng). Thử
            // lại 1 lần trước khi bỏ cuộc giúp việc "chặt chẽ hơn" ở trên không đánh đổi
            // bằng trải nghiệm kém đi khi mạng chỉ giật nhẹ 1 nhịp.
            repeat(2) { attempt ->
                val result = fetchSegmentOnce(req, segUrl, index, expectedLen, cacheKey)
                if (result.isNotEmpty()) return result
                if (attempt == 0) {
                    logW(TAG) { "fetchSegment: segIndex=$index thất bại lần 1, thử lại lần 2..." }
                }
            }
            return ByteArray(0)
        }

        private fun fetchSegmentOnce(
            req: Request,
            segUrl: String,
            index: Int,
            expectedLen: Long,
            cacheKey: String
        ): ByteArray {
            return runCatching {
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) {
                        logW(TAG) { "fetchSegment: segIndex=$index -> HTTP ${resp.code} không thành công, url=$segUrl" }
                        ByteArray(0)
                    } else {
                        val bytes = resp.body?.bytes() ?: ByteArray(0)
                        logD(TAG) { "fetchSegment: segIndex=$index THÀNH CÔNG, nhận ${bytes.size} byte (kỳ vọng $expectedLen byte)" }
                        if (bytes.size.toLong() != expectedLen) {
                            Log.e(
                                TAG,
                                "fetchSegment: segIndex=$index THẤT BẠI - nhận ${bytes.size} byte nhưng kỳ vọng " +
                                    "$expectedLen byte (segment bị cắt cụt/thừa do trục trặc mạng) -> KHÔNG cache " +
                                    "(tránh làm hỏng toàn bộ phiên phát), coi như tải thất bại lần này"
                            )
                            ByteArray(0)
                        } else {
                            synchronized(segmentByteCache) { segmentByteCache[cacheKey] = bytes }
                            bytes
                        }
                    }
                }
            }.onFailure { e ->
                logW(TAG) { "fetchSegment: segIndex=$index EXCEPTION khi tải segment (url=$segUrl): ${e.message}" }
            }.getOrDefault(ByteArray(0))
        }

        // readUInt32BE / tokenFor / md5HexOfDigits / aesCtrEncryptToIso / doubleBase64
        // đã được CHUYỂN LÊN cấp "object HydraxInterceptor" (xem phía trên, gần
        // detectCorrectTotalSize) để intercept() cũng gọi được trước khi tạo
        // SegmentSource. fetchSegment() ở trên gọi tường minh "HydraxInterceptor.tokenFor(...)"
        // (qualify rõ tên object) thay vì gọi trơn "tokenFor(...)" như bản cũ, để tránh
        // mọi nhập nhằng resolve tên giữa 2 object HydraxExtractor/HydraxInterceptor
        // vốn có vài hàm helper crypto trùng tên trong cùng file.
    }
}
