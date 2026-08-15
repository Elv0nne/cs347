package recloudstream

import android.content.SharedPreferences
import android.util.Log
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.lagradost.cloudstream3.Actor
import com.lagradost.cloudstream3.ActorData
import com.lagradost.cloudstream3.CommonActivity
import com.lagradost.cloudstream3.DubStatus
import com.lagradost.cloudstream3.ErrorLoadingException
import com.lagradost.cloudstream3.HomePageResponse
import com.lagradost.cloudstream3.LoadResponse
import com.lagradost.cloudstream3.MainAPI
import com.lagradost.cloudstream3.MainPageData
import com.lagradost.cloudstream3.MainPageRequest
import com.lagradost.cloudstream3.Score
import com.lagradost.cloudstream3.SearchResponse
import com.lagradost.cloudstream3.SubtitleFile
import com.lagradost.cloudstream3.TvType
import com.lagradost.cloudstream3.addDubStatus
import com.lagradost.cloudstream3.app
import com.lagradost.cloudstream3.mainPageOf
import com.lagradost.cloudstream3.network.CloudflareKiller
import com.lagradost.cloudstream3.newAnimeLoadResponse
import com.lagradost.cloudstream3.newAnimeSearchResponse
import com.lagradost.cloudstream3.newEpisode
import com.lagradost.cloudstream3.newHomePageResponse
import com.lagradost.cloudstream3.utils.ExtractorLink
import com.lagradost.cloudstream3.utils.ExtractorLinkType
import com.lagradost.cloudstream3.utils.Qualities
import com.lagradost.cloudstream3.utils.newExtractorLink
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody
import okio.Buffer
import java.io.IOException
import java.net.URL
import java.net.URLEncoder
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

private val mapper: ObjectMapper = jacksonObjectMapper().apply {
    configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
}

// SỬA LỖI (structured concurrency): trong Kotlin coroutines, CancellationException LÀ
// một subtype của Exception. Các khối "catch (e: Exception) { /* nuốt lỗi */ }" nằm bên
// trong những coroutine có thể bị hủy (vd. bên trong withTimeoutOrNull(), hoặc bên trong
// awaitAll() nơi 1 sibling lỗi sẽ hủy các sibling còn lại) trước đây vô tình bắt luôn cả
// CancellationException, khiến việc hủy coroutine bị "nuốt" thay vì lan truyền tiếp như
// cơ chế hủy chuẩn của coroutine yêu cầu. Hậu quả cụ thể: withTimeoutOrNull(25_000) ở
// loadLinks() có thể KHÔNG thực sự dừng được task con (vd. HydraxExtractor.getLinks())
// nếu công việc bên trong tự bắt hết Exception bao gồm cả tín hiệu hủy — task tiếp tục
// chạy ngầm tốn mạng/CPU dù bên ngoài coi như đã "hết giờ". Dùng hàm helper này ở mọi
// nơi cần bắt lỗi rộng nhưng phải cho tín hiệu hủy đi qua nguyên vẹn.
private suspend inline fun <T> catchNonCancellation(block: () -> T, onError: (Exception) -> T): T {
    return try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        currentCoroutineContext().ensureActive()
        onError(e)
    }
}

private fun toJson(value: Any?): String {
    return try {
        mapper.writeValueAsString(value)!!
    } catch (e: Exception) {
        value.toString()
    }
}

class Anime47Provider : MainAPI() {

    // TAG dùng để lọc log riêng cho provider này, vd:
    //   adb logcat -s Anime47Provider:V
    private val TAG = "Anime47Provider"

    override var mainUrl = "https://anime47.best"
    private val apiBaseUrl = "https://anime47.love/api"
    override var name = "Anime47"
    override val hasMainPage = true
    override var lang = "vi"
    override val hasDownloadSupport = true
    override val supportedTypes = setOf(TvType.Anime, TvType.Cartoon)

    private val interceptor = CloudflareKiller()

    // HIỆU NĂNG: scope nền riêng (SupervisorJob + IO dispatcher) cho các tác vụ
    // "best effort", không ảnh hưởng tới nội dung chính (điểm danh, lưu lịch sử xem).
    // SupervisorJob đảm bảo lỗi ở 1 tác vụ nền không hủy các tác vụ nền khác. Dùng scope
    // độc lập với coroutine gọi getMainPage()/loadLinks() (thay vì coroutineScope { } lồng
    // vào request chính) để việc launch những tác vụ này KHÔNG bắt request chính phải chờ
    // chúng hoàn thành trước khi trả kết quả — true fire-and-forget.
    private val backgroundScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // SỬA LỖI (race condition + đăng xuất không hoàn toàn): trước đây cachedToken là
    // "var" thường thuộc riêng instance, được đọc ở ensureToken() và ghi/null-hoá ở
    // fetchApi() (dòng "cachedToken = null") mà KHÔNG qua tokenMutex. Khi loadLinks()
    // chạy song song nhiều episode (mỗi cái tự gọi fetchApi() -> có thể tự phát hiện
    // token cũ hết hạn), nhiều coroutine có thể đồng thời set cachedToken = null ngay
    // sau khi một coroutine khác vừa login lại thành công và set token mới -> token mới
    // bị ghi đè về null, gây login lại thừa liên tục, tốn round-trip mạng.
    //
    // Đồng thời, vì token trước đây chỉ nằm trong biến instance, thao tác "Xóa thông
    // tin đăng nhập" ở màn hình cài đặt (1 class hoàn toàn tách biệt) không có cách nào
    // vô hiệu hoá được token đang cache trong provider đang chạy — tài khoản coi như
    // chưa thực sự đăng xuất khỏi phiên hiện tại. Nay dùng chung AtomicReference cấp
    // companion (Session.sharedCachedToken): vừa đọc/ghi an toàn giữa nhiều coroutine,
    // vừa cho phép Settings gọi Session.invalidateCachedSession() để đăng xuất ngay lập
    // tức instance provider đang chạy mà không cần giữ tham chiếu tới nó.
    private var cachedToken: String?
        get() = Session.sharedCachedToken.get()
        set(value) = Session.sharedCachedToken.set(value)

    // ===================== DCC: điểm danh & lưu lịch sử xem =====================
    // Xác nhận qua DevTools (bắt request thật của web anime47.love):
    //  - Điểm danh hằng ngày: gọi GET "$apiBaseUrl/dcc/info" một lần mỗi session
    //    (lần đầu getMainPage được gọi), tương đương hành vi "mở web/app" của user
    //    thật. Server tự xử lý điểm danh phía họ khi phát hiện phiên truy cập mới.
    //  - Lưu lịch sử xem: gọi POST "$apiBaseUrl/profile/history/mark-episode" với
    //    body {"episode_id": <id>} khi user mở 1 tập và lấy được link phát. Đây là
    //    hành vi thật (tương ứng "user đã mở tập này ra xem"), phản ánh đúng sự thật
    //    về phía app, không giả lập gì thêm.
    //
    // LƯU Ý QUAN TRỌNG: mark-episode CHỈ lưu lịch sử, KHÔNG phải nơi cộng điểm DCC.
    // Theo DevTools, điểm "+N DCC" thật ra được cộng bởi endpoint riêng
    // "$apiBaseUrl/dcc/watch-progress", được web gọi lặp lại mỗi ~30 giây trong lúc
    // phát với { episode_id, progress_seconds, seconds_watched: 30 }, và server chỉ
    // thưởng điểm khi progress_seconds tích lũy đạt khoảng ~80% thời lượng tập.
    // Cloudstream's loadLinks() không có cách nào biết chính xác player đang phát
    // đến giây thứ mấy hoặc user có thực sự đang xem hay không (không có hook theo
    // dõi tiến trình phát từ phía provider). Vì việc gọi watch-progress đòi hỏi báo
    // cáo thời lượng xem thực tế, ta KHÔNG giả lập heartbeat này ở đây — làm vậy sẽ
    // là gửi dữ liệu "đã xem" không có thật lên server. Do đó điểm DCC theo thời
    // gian xem sẽ KHÔNG được cộng tự động qua app; user vẫn cần xem qua web thật để
    // nhận điểm đó. Phần dưới đây chỉ xử lý điểm danh + lưu lịch sử, là 2 hành vi
    // phản ánh đúng thực tế thao tác của user trên app.
    //
    // Cả hai request đều "best effort": lỗi mạng/hết hạn token không được throw ra
    // ngoài, để không làm gián đoạn việc xem phim nếu hệ thống điểm gặp sự cố.
    private val dailyCheckinDone = AtomicBoolean(false)

    // Lưu ý: hai hàm dưới đây (triggerDailyCheckinOnce, markEpisodeWatched) chỉ được gọi
    // qua "backgroundScope.launch { ... }" (xem getMainPage()/loadEpisodeStreams()), tức
    // luôn chạy trong 1 coroutine job độc lập mà không có nơi nào await() kết quả của nó.
    // Vì vậy "catch (e: Exception)" nuốt cả CancellationException ở đây là AN TOÀN và
    // đúng ý: nếu job nền này bị hủy (vd. app tắt hẳn), nuốt lỗi chỉ khiến hàm kết thúc
    // êm thấm thay vì log lỗi không cần thiết — không có coroutine cha nào chờ tín hiệu
    // hủy này để tiếp tục logic khác. Khác với các "catch (e: Exception)" trong đường đi
    // chính (getMainPage/search/load/loadLinks) đã được sửa dùng catchNonCancellation()
    // hoặc rethrow CancellationException tường minh.
    private suspend fun triggerDailyCheckinOnce() {
        if (!dailyCheckinDone.compareAndSet(false, true)) return

        try {
            val headers = getAuthHeaders()
            if (!headers.containsKey("Authorization")) return // chưa đăng nhập, bỏ qua

            app.get(
                "$apiBaseUrl/dcc/info",
                headers = headers,
                interceptor = interceptor,
                timeout = 10000
            )
        } catch (e: Exception) {
            // Không chặn luồng chính nếu điểm danh lỗi (mạng, token hết hạn, v.v.)
        }
    }

    private suspend fun markEpisodeWatched(episodeId: Int) {
        try {
            val headers = getAuthHeaders()
            if (!headers.containsKey("Authorization")) return // chưa đăng nhập, bỏ qua

            val body = toJson(mapOf("episode_id" to episodeId))
                .toRequestBody("application/json".toMediaTypeOrNull())

            app.post(
                "$apiBaseUrl/profile/history/mark-episode",
                headers = headers + mapOf(
                    "origin" to mainUrl,
                    "referer" to "$mainUrl/"
                ),
                requestBody = body,
                interceptor = interceptor,
                timeout = 10000
            )
        } catch (e: Exception) {
            // Best effort: không làm gián đoạn việc phát video nếu báo điểm thất bại
        }
    }

    // GHI CHÚ BẢO MẬT (không sửa trong bản này để tránh phá vỡ UI cài đặt đang hoạt
    // động ổn định): mật khẩu hiện lưu dạng plaintext trong SharedPreferences thường.
    // Điều này chỉ lộ dữ liệu nếu thiết bị đã bị root/truy cập vật lý trực tiếp vào
    // filesystem của app (nằm ngoài sandbox Android bình thường) — không phải lỗ hổng
    // qua mạng. Nếu muốn nâng cấp: thay bằng androidx.security-crypto's
    // EncryptedSharedPreferences, nhưng lưu ý Anime47SettingsFragment dùng
    // PreferenceFragmentCompat với EditTextPreference đọc/ghi qua
    // preferenceManager.sharedPreferences mặc định — cần viết PreferenceDataStore tuỳ
    // chỉnh trỏ vào EncryptedSharedPreferences rồi gọi preferenceManager.preferenceDataStore
    // = ... để cả 2 phía (đọc ở đây, ghi ở SettingsFragment) luôn dùng chung 1 store.
    private val prefs: SharedPreferences?
        get() {
            val activity = CommonActivity.activity ?: return null
            return activity.getSharedPreferences("anime47_prefs", android.content.Context.MODE_PRIVATE)
        }

    override val mainPage: List<MainPageData> = mainPageOf(
        "/anime/filter?lang=vi&sort=latest" to "Anime Mới Cập Nhật",
        "/anime/filter?lang=vi&sort=rating" to "Top Đánh Giá",
        "/anime/filter?lang=vi&type=tv" to "Anime TV",
        "/anime/filter?lang=vi&type=movie" to "Anime Movie"
    )

    private val subtitleLanguageMap: Map<String, List<String>> = mapOf(
        "Vietnamese" to listOf("tiếng việt", "vietnamese", "vietsub", "viet", "vi"),
        "English" to listOf("tiếng anh", "english", "engsub", "eng", "en")
    )

    // ===================== Helper methods =====================

    private fun fixUrl(url: String?): String? {
        if (url.isNullOrBlank()) return null
        if (url.contains("via.placeholder.com", ignoreCase = true)) return null
        if (url.startsWith("http", ignoreCase = true)) return url
        if (url.startsWith("//")) return "https:$url"

        val path = if (url.startsWith("/")) url else "/$url"
        return if (mainUrl.startsWith("http", ignoreCase = true)) {
            "$mainUrl$path"
        } else {
            "https:$mainUrl$path"
        }
    }

    private fun createSearchResponse(
        title: String,
        poster: String?,
        link: String,
        year: Int? = null,
        episodesStr: String? = null
    ): SearchResponse {
        val episodes: Int? = episodesStr?.let { str ->
            val digitsOnly = str.filter { it.isDigit() }
            digitsOnly.toIntOrNull()
        }

        return newAnimeSearchResponse(title, link, TvType.Anime) {
            this.posterUrl = fixUrl(poster)
            this.year = year
            if (episodes != null) {
                addDubStatus(DubStatus.Subbed, episodes)
            }
        }
    }

    private fun toTvType(detail: DetailPost): TvType {
        // Lưu ý: luôn trả về TvType.Anime (hoặc Cartoon) thay vì TvType.AnimeMovie / TvType.OVA.
        // Lý do: CloudStream hiển thị UI "single play" (không có danh sách tập) cho các
        // TvType thuộc nhóm Movie/OVA, nên nếu một "movie" trên Anime47 thực chất có nhiều
        // tập/phần (rất phổ biến với OVA, special, hoặc movie nhiều phần), toàn bộ các tập
        // từ tập 2 trở đi sẽ bị ẩn khỏi người dùng ("mất tập"). Dùng TvType.Anime cho mọi
        // trường hợp để app luôn hiển thị danh sách tập đầy đủ, kể cả khi chỉ có 1 tập.
        return when {
            detail.title != null && detail.title.contains("Hoạt Hình Trung Quốc", ignoreCase = true) -> TvType.Cartoon
            else -> TvType.Anime
        }
    }

    private fun mapSubtitleLabel(label: String): String {
        val trimmedLower = label.trim().lowercase(Locale.ROOT)
        if (trimmedLower.isBlank()) return "Subtitle"

        for ((standardName, keywords) in subtitleLanguageMap) {
            if (keywords.any { trimmedLower.contains(it) }) {
                return standardName
            }
        }

        val trimmed = label.trim()
        return if (trimmed.isNotEmpty()) {
            val firstChar = trimmed[0]
            val firstCharUpper = if (firstChar.isLowerCase()) {
                firstChar.titlecase(Locale.ROOT)
            } else {
                firstChar.toString()
            }
            firstCharUpper + trimmed.substring(1)
        } else {
            trimmed
        }
    }

    private fun findMpegTsOffset(data: ByteArray): Int {
        val packetSize = 188
        val minLen = packetSize * 3
        if (data.size < minLen) return -1

        // SỬA LỖI (off-by-one): giới hạn trên phải là "data.size - minLen" bao gồm cả vị
        // trí cuối cùng còn đủ chỗ cho 3 gói 188 byte liên tiếp, tức index i thoả
        // i + minLen <= data.size  =>  i <= data.size - minLen. Bản gốc dùng
        // "0 until (data.size - minLen)" (loại trừ chặn trên) nên bỏ sót đúng vị trí i =
        // data.size - minLen — trường hợp dễ gặp nhất là khi offset hợp lệ nằm ở cuối
        // buffer (ví dụ data.size đúng bằng minLen, tức chỉ có duy nhất 1 vị trí hợp lệ
        // là i = 0), khiến hàm trả về -1 (không sửa được offset) dù dữ liệu hợp lệ.
        val lastValidIndex = data.size - minLen
        for (i in 0..lastValidIndex) {
            if (data[i] == 0x47.toByte() &&
                data[i + packetSize] == 0x47.toByte() &&
                data[i + packetSize * 2] == 0x47.toByte()
            ) {
                return i
            }
        }
        return -1
    }

    // Token từ Anime47 có thời hạn ngắn (JWT hết hạn sau một khoảng thời gian).
    // Trước đây token được cache mãi mãi trong biến instance (cachedToken) và không
    // bao giờ được làm mới, dẫn tới lỗi: xem được vài tập/video rồi API bắt đầu trả
    // về "PRIVATE_MODE" (token đã hết hạn) và app quăng lỗi yêu cầu người dùng tự vào
    // cài đặt đăng nhập lại. Sửa: khi phát hiện token cũ không còn dùng được, tự động
    // login lại bằng email/password đã lưu (forceRefresh = true), hoàn toàn trong nền,
    // và chỉ retry request một lần thay vì bắt người dùng thao tác thủ công.
    private val tokenMutex = Mutex()

    // staleToken: khi forceRefresh=true, đây là token mà caller đã thấy bị server từ
    // chối (hết hạn/401). Dùng để so sánh dưới lock thay vì luôn luôn login lại — nếu
    // một coroutine khác đã kịp login lại và cachedToken hiện tại KHÁC staleToken (tức
    // đã có token mới hơn), coroutine hiện tại tái sử dụng luôn token đó thay vì gọi
    // /auth/login thêm một lần nữa. Tránh trường hợp N coroutine cùng phát hiện 1 token
    // hết hạn (vd. N tập phim tải song song) và tạo N request login trùng lặp thay vì 1.
    private suspend fun ensureToken(forceRefresh: Boolean = false, staleToken: String? = null): String? {
        if (!forceRefresh) {
            val existing = cachedToken
            if (!existing.isNullOrBlank()) {
                Log.d(TAG, "ensureToken: dùng token đã cache (forceRefresh=false)")
                return existing
            }
        }

        Log.d(TAG, "ensureToken: cần lấy token mới (forceRefresh=$forceRefresh), chờ tokenMutex")
        // Mutex tránh trường hợp nhiều coroutine (vd. loadLinks chạy song song cho
        // nhiều episodeId) cùng phát hiện token hết hạn và spam login song song.
        return tokenMutex.withLock {
            Log.d(TAG, "ensureToken: đã giành được tokenMutex")
            // Sau khi giành được lock, kiểm tra lại: có thể một coroutine khác đã
            // login lại thành công trong lúc chờ, nên không cần login lại lần nữa.
            val existing = cachedToken
            if (!forceRefresh) {
                if (!existing.isNullOrBlank()) {
                    Log.d(TAG, "ensureToken: token đã được coroutine khác cập nhật trong lúc chờ lock, dùng luôn")
                    return@withLock existing
                }
            } else if (!existing.isNullOrBlank() && existing != staleToken) {
                // Một coroutine khác đã login lại thành công với token mới (khác với
                // token mà caller này biết là đã hỏng) trong lúc chờ lock -> dùng luôn,
                // không cần gọi /auth/login thêm lần nữa.
                Log.d(TAG, "ensureToken: coroutine khác đã login lại thành công với token mới trong lúc chờ lock, bỏ qua login lại")
                return@withLock existing
            }

            val email = prefs?.getString("anime47_email", "") ?: ""
            val password = prefs?.getString("anime47_password", "") ?: ""

            if (email.isBlank() || password.isBlank()) {
                Log.w(TAG, "ensureToken: DỪNG - chưa cấu hình email/password trong Settings, không thể đăng nhập")
                return@withLock null
            }

            try {
                Log.d(TAG, "ensureToken: gọi POST $apiBaseUrl/auth/login cho email=$email")
                val body = toJson(LoginRequest(email, password))
                    .toRequestBody("application/json".toMediaTypeOrNull())

                val response = app.post(
                    "$apiBaseUrl/auth/login",
                    headers = mapOf(
                        "origin" to mainUrl,
                        "referer" to "$mainUrl/"
                    ),
                    requestBody = body,
                    interceptor = interceptor,
                    timeout = 15000
                )
                Log.d(TAG, "ensureToken: /auth/login trả về HTTP code=${response.code} successful=${response.isSuccessful}")

                val loginResponse: LoginResponse = mapper.readValue(
                    response.text,
                    object : TypeReference<LoginResponse>() {}
                )
                val newToken = loginResponse.access_token
                if (!newToken.isNullOrBlank()) {
                    cachedToken = newToken
                    Log.d(TAG, "ensureToken: login THÀNH CÔNG, đã cập nhật cachedToken (độ dài=${newToken.length})")
                } else {
                    Log.e(TAG, "ensureToken: THẤT BẠI - /auth/login trả về access_token rỗng/null. Response 300 ký tự đầu: ${response.text.take(300)}")
                }
                newToken
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "ensureToken: THẤT BẠI - exception khi gọi /auth/login: ${e.message}", e)
                null
            }
        }
    }

    private suspend fun getAuthHeaders(forceRefresh: Boolean = false, staleToken: String? = null): Map<String, String> {
        val token = ensureToken(forceRefresh, staleToken)
        return if (token != null) {
            mapOf("Authorization" to "Bearer $token")
        } else {
            Log.d(TAG, "getAuthHeaders: không có token khả dụng, trả về headers rỗng (request sẽ đi không kèm Authorization)")
            emptyMap()
        }
    }

    private fun looksExpiredOrUnauthorized(text: String): Boolean {
        return text.contains("\"PRIVATE_MODE\"") ||
            text.contains("\"UNAUTHORIZED\"", ignoreCase = true) ||
            text.contains("\"unauthorized\"", ignoreCase = true) ||
            text.contains("\"TOKEN_EXPIRED\"", ignoreCase = true) ||
            text.contains("jwt expired", ignoreCase = true)
    }

    private suspend inline fun <reified T> fetchApi(url: String): T {
        Log.d(TAG, "fetchApi: GET url=$url")
        val headers = getAuthHeaders()
        val firstResponse = try {
            app.get(
                url,
                headers = headers,
                interceptor = interceptor,
                timeout = 15000
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "fetchApi: THẤT BẠI - lỗi mạng khi GET url=$url: ${e.message}", e)
            throw e
        }
        Log.d(TAG, "fetchApi: url=$url trả về HTTP code=${firstResponse.code} successful=${firstResponse.isSuccessful}")

        var text = firstResponse.text

        // Token cũ không còn hợp lệ (hết hạn hoặc bị thu hồi) hoặc request trả về mã
        // 401: xoá cache, ép đăng nhập lại một lần rồi thử lại request thay vì bắt
        // người dùng tự vào cài đặt đăng nhập lại.
        val looksStale = looksExpiredOrUnauthorized(text) || firstResponse.code == 401
        if (looksStale) {
            Log.w(TAG, "fetchApi: url=$url phát hiện token hết hạn/không hợp lệ (code=${firstResponse.code}), thử đăng nhập lại rồi retry 1 lần")
            // SỬA LỖI (race condition): không còn "cachedToken = null" ở đây ngoài
            // mutex — thao tác này trước đây có thể vô tình xoá mất token mới mà một
            // coroutine khác vừa login lại thành công (xem ghi chú tại ensureToken()).
            // Thay vào đó truyền token cũ (đã biết là hỏng) vào ensureToken() để nó tự
            // quyết định dưới lock: chỉ login lại nếu cachedToken hiện tại vẫn đúng là
            // token hỏng này; nếu đã có ai đó thay bằng token mới hơn thì dùng luôn.
            val staleToken = headers["Authorization"]?.removePrefix("Bearer ")
            val retryHeaders = getAuthHeaders(forceRefresh = true, staleToken = staleToken)

            // Nếu retryHeaders không có Authorization, có 2 khả năng: (a) chưa từng
            // đăng nhập từ đầu -> giữ nguyên lỗi gốc là đúng ý; hoặc (b) đã có tài
            // khoản lưu nhưng login lại thất bại thật sự (sai mật khẩu đã lưu, hoặc
            // mất mạng ngay lúc login) -> cũng không có gì để retry thêm, giữ nguyên
            // response gốc (text) là lựa chọn hợp lý duy nhất; looksExpiredOrUnauthorized()
            // bên dưới sẽ bắt lại và báo lỗi rõ ràng cho người dùng trong cả hai trường hợp.
            if (retryHeaders.containsKey("Authorization")) {
                Log.d(TAG, "fetchApi: retry GET url=$url với token mới")
                val retryResponse = app.get(
                    url,
                    headers = retryHeaders,
                    interceptor = interceptor,
                    timeout = 15000
                )
                Log.d(TAG, "fetchApi: retry url=$url trả về HTTP code=${retryResponse.code} successful=${retryResponse.isSuccessful}")
                text = retryResponse.text
            } else {
                Log.w(TAG, "fetchApi: url=$url không retry được vì không lấy được token mới (chưa đăng nhập hoặc login lại thất bại)")
            }
        }

        if (looksExpiredOrUnauthorized(text)) {
            Log.e(TAG, "fetchApi: DỪNG - url=$url vẫn báo cần đăng nhập sau khi retry. 300 ký tự đầu response: ${text.take(300)}")
            throw ErrorLoadingException("Trang web yêu cầu đăng nhập. Vui lòng mở cài đặt tiện ích để cấu hình tài khoản.")
        }

        return try {
            mapper.readValue(text, object : TypeReference<T>() {})
        } catch (e: Exception) {
            Log.e(TAG, "fetchApi: THẤT BẠI - không parse được JSON từ url=$url: ${e.message}. 300 ký tự đầu response: ${text.take(300)}", e)
            throw e
        }
    }

    override suspend fun getMainPage(
        page: Int,
        request: MainPageRequest
    ): HomePageResponse {
        val url = "$apiBaseUrl${request.data}&page=$page"

        // HIỆU NĂNG: trước đây "triggerDailyCheckinOnce()" được await() TUẦN TỰ trước
        // khi bắt đầu fetch nội dung trang chủ — dù bản thân hàm này đã "best effort"
        // (nuốt mọi lỗi bên trong), việc await() nó vẫn cộng dồn thêm độ trễ round-trip
        // mạng thật sự vào thời gian mở app lần đầu, trong khi điểm danh không có quan hệ
        // phụ thuộc dữ liệu nào với việc tải danh sách phim. launch() trên backgroundScope
        // (không phải coroutineScope{} lồng vào đây) để nó thực sự chạy độc lập, không
        // khiến getMainPage() phải chờ nó xong mới trả kết quả cho người dùng.
        backgroundScope.launch { triggerDailyCheckinOnce() }

        // SỬA LỖI: trước đây MỌI exception (kể cả lỗi mạng thật sự: timeout, mất kết
        // nối, DNS lỗi...) đều bị nuốt thành "response = null", rồi bên dưới báo nhầm
        // là "Cấu trúc dữ liệu đã thay đổi hoặc tài khoản chưa kích hoạt" — làm người
        // dùng/nhà phát triển hiểu sai nguyên nhân thật (vd. tưởng server đổi API trong
        // khi chỉ là mất mạng tạm thời) và không có cách nào phân biệt hai trường hợp.
        // Chỉ nuốt lỗi parse/dữ liệu (không phải lỗi mạng) ở đây; để lỗi mạng (IOException
        // và các lỗi không phải do parse) thoát ra ngoài với thông tin gốc. Dùng
        // catchNonCancellation() để không nuốt nhầm tín hiệu hủy coroutine (xem ghi chú
        // tại khai báo hàm này).
        val response: ApiFilterResponse? = try {
            fetchApi(url)
        } catch (e: ErrorLoadingException) {
            throw e
        } catch (e: IOException) {
            throw ErrorLoadingException("Không thể kết nối tới máy chủ Anime47. Vui lòng kiểm tra kết nối mạng và thử lại.")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Lỗi parse JSON hoặc cấu trúc dữ liệu bất ngờ: coi như response rỗng,
            // xử lý tiếp bên dưới với thông báo phù hợp.
            null
        }

        val posts = response?.data?.posts
            ?: throw ErrorLoadingException("Cấu trúc dữ liệu trang chủ đã thay đổi hoặc tài khoản chưa kích hoạt.")

        val items = posts.mapNotNull { post ->
            val link = fixUrl(post.link) ?: return@mapNotNull null
            createSearchResponse(
                post.title,
                post.poster,
                link,
                post.year?.toIntOrNull(),
                post.current_episode ?: post.episodes
            )
        }

        return newHomePageResponse(request.name, items, items.size >= 24)
    }

    override suspend fun search(query: String): List<SearchResponse> {
        val encoded = URLEncoder.encode(query, "UTF-8")
        val url = "$apiBaseUrl/search/full/?lang=vi&keyword=$encoded&page=1"

        // SỬA LỖI: tương tự getMainPage(), lỗi mạng thật sự trước đây bị nuốt im lặng
        // thành "không có kết quả" (emptyList()), khiến người dùng tưởng tìm kiếm không
        // ra gì trong khi thực chất là mất kết nối/timeout. Chỉ coi là "không có kết
        // quả" khi lỗi đến từ parse/dữ liệu; lỗi mạng được báo rõ ràng.
        val response: ApiSearchResponse? = try {
            fetchApi(url)
        } catch (e: ErrorLoadingException) {
            throw e
        } catch (e: IOException) {
            throw ErrorLoadingException("Không thể kết nối tới máy chủ Anime47. Vui lòng kiểm tra kết nối mạng và thử lại.")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        }

        val results = response?.results ?: return emptyList()

        return results.mapNotNull { item ->
            val link = fixUrl(item.link) ?: return@mapNotNull null
            createSearchResponse(
                item.title,
                item.image,
                link,
                null,
                item.current_episode ?: item.episodes
            )
        }
    }

    override suspend fun load(url: String): LoadResponse {
        // HIỆU NĂNG: dùng animeIdRegex ở cấp companion (biên dịch 1 lần duy nhất khi
        // class được load) thay vì tạo Regex mới mỗi lần load() được gọi (tức mỗi lần
        // người dùng mở 1 trang chi tiết phim) — cùng tinh thần tối ưu đã áp dụng cho
        // cdnFixRegex, tránh chi phí compile regex lặp lại không cần thiết.
        val animeId = animeIdRegex
            .find(url.trimEnd('/'))
            ?.groupValues
            ?.get(1)

        if (animeId.isNullOrBlank() || animeId.toIntOrNull() == null) {
            throw IllegalArgumentException("Invalid anime ID from URL")
        }

        try {
            val (infoResponse, episodeResponse, recsResponse) = coroutineScope {
                val infoTask = async {
                    fetchApi<ApiDetailResponse>("$apiBaseUrl/anime/info/$animeId?lang=vi")
                }
                val episodesTask = async {
                    fetchApi<ApiEpisodeResponse>("$apiBaseUrl/anime/$animeId/episodes?lang=vi")
                }
                // SỬA LỖI: "recommendations" chỉ là dữ liệu phụ (gợi ý phim liên quan),
                // không thiết yếu để xem phim. Trước đây recsTask.await() nằm chung
                // trong cùng 1 khối với info/episodes nên nếu endpoint recommendations
                // lỗi/timeout (vốn dễ chập chờn hơn vì không quan trọng bằng, có thể bị
                // server ưu tiên thấp hơn), toàn bộ load() ném exception khiến người
                // dùng KHÔNG xem được phim dù title + danh sách tập vẫn tải bình thường.
                // Bắt lỗi riêng cho recsTask, coi recommendations rỗng nếu lỗi thay vì
                // làm hỏng toàn bộ trang chi tiết phim.
                //
                // SỬA LỖI (structured concurrency): recsTask nằm trong cùng coroutineScope
                // với infoTask/episodesTask — nếu 1 trong 2 task đó lỗi, coroutineScope sẽ
                // tự hủy các sibling còn lại (bao gồm recsTask). "catch (e: Exception)"
                // trần trước đây sẽ nuốt luôn CancellationException đó, khiến recsTask
                // tiếp tục gọi mạng dù phần còn lại của load() đã thất bại và sắp bị vứt
                // bỏ — vừa lãng phí băng thông vừa làm coroutineScope phải chờ 1 request
                // không còn ý nghĩa gì hoàn tất trước khi thực sự ném lỗi ra ngoài.
                val recsTask = async {
                    try {
                        fetchApi<ApiRecommendationResponse>("$apiBaseUrl/anime/info/$animeId/recommendations?lang=vi")
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        null
                    }
                }
                Triple(infoTask.await(), episodesTask.await(), recsTask.await())
            }

            val detail = infoResponse?.data ?: throw IOException("Data is null")

            val title = detail.title ?: "Unknown Title"
            val posterUrl = fixUrl(detail.poster)
            val plot = detail.description
            val tags = detail.genres
                ?.mapNotNull { it.name }
                ?.filter { it.isNotBlank() }
            val year = detail.year?.toIntOrNull()
            val tvType = toTvType(detail)
            val score = detail.score?.toString()?.let { Score.from10(it) }

            val actors = detail.characters?.mapNotNull { character ->
                val name = character.name ?: return@mapNotNull null
                ActorData(
                    Actor(name, fixUrl(character.image_url)),
                    roleString = character.role
                )
            }

            val episodeItems = episodeResponse?.teams
                ?.flatMap { it.groups }
                ?.flatMap { it.episodes }
                ?.filter { it.number != null }

            val episodes = if (episodeItems != null) {
                episodeItems
                    .groupBy { it.number!! }
                    .map { (number, items) ->
                        val ids = items.map { it.id }.distinct()
                        val data = toJson(ids)
                        newEpisode(data) {
                            this.name = "Tập $number"
                            this.episode = number
                        }
                    }
                    .sortedBy { it.episode }
            } else {
                emptyList()
            }

            val recommendations = recsResponse?.data?.mapNotNull { item ->
                val link = fixUrl(item.link) ?: return@mapNotNull null
                createSearchResponse(
                    item.title ?: "",
                    item.poster,
                    link,
                    item.year?.toIntOrNull(),
                    item.current_episode ?: item.episodes
                )
            }

            return newAnimeLoadResponse(title, url, tvType) {
                this.posterUrl = posterUrl
                this.plot = plot
                this.tags = tags
                this.year = year
                this.score = score
                this.actors = actors
                this.recommendations = recommendations
                this.episodes = mutableMapOf(DubStatus.Subbed to episodes)
            }
        } catch (e: ErrorLoadingException) {
            // SỬA LỖI: ErrorLoadingException do fetchApi() ném ra khi phát hiện cần
            // đăng nhập (token hết hạn/không hợp lệ và tự động login lại thất bại)
            // trước đây bị catch (Exception) bên dưới nuốt mất và bọc lại thành một
            // IOException chung chung ("Lỗi tải thông tin phim: ..."), làm mất đi
            // thông báo rõ ràng "Vui lòng mở cài đặt tiện ích để cấu hình tài khoản"
            // mà CloudStream có thể xử lý/hiển thị khác biệt so với lỗi I/O thông
            // thường. Cho lỗi này xuyên qua nguyên vẹn, nhất quán với cách getMainPage()
            // và search() đã xử lý.
            throw e
        } catch (e: CancellationException) {
            // SỬA LỖI: không bọc CancellationException thành IOException — làm vậy sẽ
            // biến 1 tín hiệu hủy coroutine hợp lệ (vd. người dùng thoát màn hình chi
            // tiết phim trước khi load() xong) thành 1 lỗi I/O "thật", có thể khiến
            // CloudStream hiển thị nhầm thông báo lỗi cho người dùng dù không có gì sai.
            throw e
        } catch (e: Exception) {
            throw IOException("Lỗi tải thông tin phim: ${e.message}", e)
        }
    }

    override suspend fun loadLinks(
        data: String,
        isCasting: Boolean,
        subtitleCallback: (SubtitleFile) -> Unit,
        callback: (ExtractorLink) -> Unit
    ): Boolean {
        Log.d(TAG, "loadLinks: BẮT ĐẦU data=$data")

        val episodeIds: List<Int> = try {
            if (data.startsWith("[")) {
                mapper.readValue(data, object : TypeReference<List<Int>>() {})
            } else {
                listOf(data.toInt())
            }
        } catch (e: Exception) {
            Log.e(TAG, "loadLinks: DỪNG - không parse được data='$data' thành episodeId(s): ${e.message}", e)
            return false
        }

        Log.d(TAG, "loadLinks: episodeIds=$episodeIds")
        if (episodeIds.isEmpty()) {
            Log.w(TAG, "loadLinks: DỪNG - episodeIds rỗng")
            return false
        }

        val loaded = AtomicBoolean(false)
        val referer = "$mainUrl/"

        // HIỆU NĂNG: các episode được xử lý song song với nhau (map { async { ... } }),
        // và bên trong mỗi episode, mọi server FE/HY của episode đó cũng chạy song song
        // (xem loadEpisodeStreams). Tổng thời gian loadLinks() chỉ còn phụ thuộc vào
        // request/server chậm nhất trong toàn bộ tập hợp, thay vì tổng dồn tuần tự.
        //
        // ĐỘ ỔN ĐỊNH: mỗi episode được bọc trong withTimeoutOrNull(25s) — nếu không có
        // giới hạn này, một server bị treo (CDN không phản hồi nhưng không đóng kết nối
        // để trigger timeout ở tầng OkHttp) có thể khiến awaitAll() bên ngoài chờ vô
        // thời hạn dù các episode/server khác đã xong từ lâu.
        //
        // SỬA LỖI (ngân sách thời gian không khớp): trước đây comment ở đây ước tính "15s
        // watch-info + embed 15s + 1 retry" là đủ trong 25s, nhưng đó là phép cộng sai —
        // watch-info (fetchApi, timeout=15s) chạy TRƯỚC, rồi các stream mới chạy song
        // song, và bên trong nhánh HY, fetchMp4Metadata() có thể tự gọi app.get() TUẦN
        // TỰ tới 2 lần (mỗi lần timeout riêng) nếu lần đầu lỗi/5xx. Trường hợp xấu nhất
        // thực tế là watch-info (tới 15s) + embed lần 1 (tới HY_EMBED_TIMEOUT_MS) + embed
        // lần 2 (tới HY_EMBED_TIMEOUT_MS) chạy TUẦN TỰ trong cùng 1 coroutine con — với
        // giá trị 15s cũ cho mỗi lần embed, tổng có thể lên tới 15+15+15=45s, vượt xa
        // ngân sách 25s và khiến withTimeoutOrNull hủy giữa chừng oan uổng dù server đang
        // phản hồi chậm nhưng vẫn trong giới hạn hợp lý của chính nó. Hạ timeout mỗi lần
        // gọi embed xuống HY_EMBED_TIMEOUT_MS (8s) để tổng trường hợp xấu nhất
        // (15 + 8 + 8 = 31s vẫn hơi vượt, nên đồng thời nới outer timeout xuống còn phụ
        // thuộc vào EPISODE_TIMEOUT_MS bên dưới thay vì hằng số rời rạc) — xem
        // EPISODE_TIMEOUT_MS.
        coroutineScope {
            episodeIds.map { id ->
                async {
                    withTimeoutOrNull(EPISODE_TIMEOUT_MS) {
                        loadEpisodeStreams(id, referer, loaded, subtitleCallback, callback)
                    }
                }
            }.awaitAll()
        }

        Log.d(TAG, "loadLinks: KẾT THÚC - loaded=${loaded.get()} cho episodeIds=$episodeIds")
        return loaded.get()
    }

    /** Tải toàn bộ server (FE/HY/...) của một episode, chạy song song với nhau. */
    private suspend fun loadEpisodeStreams(
        episodeId: Int,
        referer: String,
        loaded: AtomicBoolean,
        subtitleCallback: (SubtitleFile) -> Unit,
        callback: (ExtractorLink) -> Unit
    ) {
        // SỬA LỖI (structured concurrency): dùng catchNonCancellation() thay vì
        // "catch (e: Exception)" trần — xem ghi chú đầy đủ tại khai báo hàm helper ở đầu
        // file. Quan trọng nhất cho hàm này vì nó luôn được gọi bên trong
        // withTimeoutOrNull(25_000) ở loadLinks(): nếu lỗi mạng thật sự xảy ra CÙNG LÚC
        // timeout kích hoạt, catch trần trước đây có thể vô tình nuốt luôn tín hiệu hủy
        // do timeout gửi xuống, khiến coroutine (và bất kỳ awaitAll() con nào bên trong)
        // không dừng đúng lúc như kỳ vọng.
        catchNonCancellation({
            Log.d(TAG, "loadEpisodeStreams: episodeId=$episodeId gọi watch-info API")
            val watchResponse: ApiWatchResponse? =
                fetchApi("$apiBaseUrl/anime/watch/episode/$episodeId?lang=vi")
            val streams = watchResponse?.streams
            if (streams == null) {
                Log.e(TAG, "loadEpisodeStreams: episodeId=$episodeId DỪNG - watch-info trả về null hoặc không có 'streams' (watchResponse=$watchResponse)")
                return@catchNonCancellation
            }
            Log.d(TAG, "loadEpisodeStreams: episodeId=$episodeId nhận được ${streams.size} stream(s): ${streams.map { it.server_name to it.player_type }}")

            val episodeLoaded = coroutineScope {
                streams.map { stream ->
                    async { loadSingleStream(stream, referer, loaded, subtitleCallback, callback) }
                }.awaitAll().any { it }
            }
            Log.d(TAG, "loadEpisodeStreams: episodeId=$episodeId hoàn tất, episodeLoaded=$episodeLoaded")

            // Báo "đã xem" lên hệ thống DCC chỉ khi thực sự lấy được ít nhất 1 link
            // phát cho episode này (tránh cộng điểm cho tập lỗi/rỗng).
            //
            // HIỆU NĂNG: chạy nền (backgroundScope.launch, không await) thay vì chờ
            // tuần tự — markEpisodeWatched() là "best effort" (đã tự nuốt lỗi bên
            // trong), người dùng đã có link phát rồi nên không có lý do gì để loadLinks()
            // phải trì hoãn trả về (và do đó trì hoãn việc player bắt đầu phát) chỉ để
            // chờ 1 request ghi log lịch sử xem hoàn tất.
            if (episodeLoaded) {
                backgroundScope.launch { markEpisodeWatched(episodeId) }
            }
        }, onError = { e ->
            // bỏ qua lỗi từng episode riêng lẻ, không chặn các episode khác
            Log.e(TAG, "loadEpisodeStreams: episodeId=$episodeId LỖI: ${e.message}", e)
        })
    }

    /** Tải một server/stream đơn lẻ (FE hoặc HY) và forward link/subtitle qua callback. */
    private suspend fun loadSingleStream(
        stream: Stream,
        referer: String,
        loaded: AtomicBoolean,
        subtitleCallback: (SubtitleFile) -> Unit,
        callback: (ExtractorLink) -> Unit
    ): Boolean {
        val url = stream.url
        Log.d(TAG, "loadSingleStream: server=${stream.server_name} player_type=${stream.player_type} url=$url")
        if (url == null || url.isBlank()) {
            Log.w(TAG, "loadSingleStream: bỏ qua server=${stream.server_name} vì url rỗng/null")
            return false
        }

        fun forwardSubtitles() {
            stream.subtitles?.forEach { subtitle ->
                if (!subtitle.file.isNullOrBlank()) {
                    subtitleCallback(SubtitleFile(mapSubtitleLabel(subtitle.label ?: "Vietnamese"), subtitle.file))
                }
            }
        }

        // Server "HY" (Hydrax/Abyss.to) không trả về m3u8 thật, mà là một trang embed
        // chứa metadata mã hóa AES-CTR (xem HydraxExtractor.kt). Phải đi qua
        // HydraxExtractor + HydraxInterceptor thay vì coi url là m3u8 trực tiếp.
        if (HydraxExtractor.isHydraxUrl(url)) {
            Log.d(TAG, "loadSingleStream: server=${stream.server_name} nhận diện là HY (Hydrax), gọi HydraxExtractor.getLinks")
            // SỬA LỖI (structured concurrency): xem ghi chú tại catchNonCancellation() —
            // giữ nguyên tín hiệu hủy (timeout/sibling lỗi trong awaitAll) thay vì để
            // catch trần nuốt mất, đặc biệt quan trọng vì HydraxExtractor.getLinks() có
            // thể tự thực hiện tới 2 lần gọi mạng tuần tự (retry 1 lần trong
            // fetchMp4Metadata), là nhánh dễ vượt quá ngân sách thời gian cho phép nhất.
            val hyLoaded = catchNonCancellation({
                val hydraxLinks = HydraxExtractor.getLinks(
                    streamUrl = url,
                    providerName = name,
                    serverName = stream.server_name,
                    referer = referer
                )
                hydraxLinks.forEach { callback(it) }
                Log.d(TAG, "loadSingleStream: server=${stream.server_name} HY trả về ${hydraxLinks.size} link")
                hydraxLinks.isNotEmpty()
            }, onError = { e ->
                Log.e(TAG, "loadSingleStream: server=${stream.server_name} HY LỖI: ${e.message}", e)
                false // bỏ qua lỗi riêng của HY, không chặn các server khác
            })
            if (hyLoaded) loaded.set(true)
            forwardSubtitles()
            return hyLoaded
        }

        // Chấp nhận mọi server có URL hợp lệ (FE, HY, hoặc bất kỳ server nào khác),
        // thay vì chỉ giới hạn ở "FE"/jwplayer.
        Log.d(TAG, "loadSingleStream: server=${stream.server_name} nhận diện là FE/khác (không phải HY), xử lý như m3u8 trực tiếp")

        // SỬA LỖI (root cause thật sự — đã xác nhận qua nhiều vòng chẩn đoán): trên
        // trình duyệt web, tập phim này phát FE bình thường; qua app lại nhận về ảnh
        // PNG THẬT hợp lệ (không phải trang chặn Cloudflare, không phải segment TS giả
        // trang — đã loại trừ cả 2 khả năng bằng log chẩn đoán chi tiết) thay vì segment
        // video mỗi khi tải segment từ CDN "nonprofit.asia". Khác biệt mấu chốt giữa
        // trình duyệt và app: trình duyệt TỰ ĐỘNG giữ và gửi lại cookie session (thường
        // do Cloudflare hoặc chính CDN set ở lần request m3u8/embed đầu tiên) cho mọi
        // request segment tiếp theo, kể cả sang domain CDN khác (nonprofit.asia) nếu
        // cookie đó có domain/scope phù hợp. Ngược lại, OkHttpClient dùng bởi
        // getVideoInterceptor() (chạy trong pipeline ExoPlayer) là MỘT INSTANCE HOÀN
        // TOÀN KHÁC với client nội bộ của app.get() — không chia sẻ CookieJar, nên
        // cookie nhận được ở bước preflight bên dưới không bao giờ tới được request
        // segment thật của player. CDN thiếu cookie hợp lệ coi đây là truy cập
        // hotlink/không hợp lệ và trả về ảnh placeholder (PNG thật, hợp lệ, nhưng không
        // phải nội dung media) thay vì segment thật. Sửa: đọc header Set-Cookie từ
        // chính response preflight (m3u8 gốc) và gắn thủ công vào header "Cookie" của
        // ExtractorLink, để cookie được gửi kèm dưới dạng header tĩnh cho MỌI request
        // tiếp theo của player (bao gồm cả request tới domain CDN segment khác), bất kể
        // OkHttpClient nào xử lý request đó.
        var cookieHeader: String? = null

        val headers = mutableMapOf(
            "Referer" to referer,
            "User-Agent" to "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "sec-ch-ua" to "\"Chromium\";v=\"120\", \"Not?A_Brand\";v=\"24\"",
            "sec-ch-ua-mobile" to "?1",
            "sec-ch-ua-platform" to "\"Android\""
        )

        if (url.contains("vlogphim.net")) {
            headers["Origin"] = referer
            headers["authority"] = runCatching { URL(url).host }.getOrDefault("pl.vlogphim.net")
            Log.d(TAG, "loadSingleStream: server=${stream.server_name} nhận diện url vlogphim.net, thêm header Origin/authority")
        }

        Log.d(TAG, "loadSingleStream: server=${stream.server_name} headers cuối cùng: $headers")

        // CHẨN ĐOÁN (log thực tế cho thấy ExoPlayer báo "Cannot find sync byte. Most
        // likely not a Transport Stream" khi phát link FE/vlogphim.net — tức nội dung
        // server trả về không phải .m3u8/TS thật như code đang giả định qua
        // ExtractorLinkType.M3U8, nhưng lỗi này chỉ lộ ra bên trong ExoPlayer, ngoài
        // tầm với của log provider). Gọi thử GET trước khi giao link cho player, chỉ
        // đọc phần đầu response (không tải hết file/segment lớn) để log HTTP code,
        // Content-Type, và vài trăm ký tự/byte đầu — đủ để biết url thật sự trả về gì
        // (m3u8 thật, JSON, HTML lỗi, hay định dạng khác) mà KHÔNG đổi hành vi callback
        // hiện tại (vẫn gửi link như cũ dù preflight thất bại, vì chưa rõ format thật
        // để tự ý xử lý khác).
        catchNonCancellation({
            val preflight = app.get(
                url,
                headers = headers,
                interceptor = interceptor,
                timeout = 10000
            )
            val contentType = preflight.headers["Content-Type"] ?: preflight.headers["content-type"]
            val bodyPreview = runCatching { preflight.text.take(200) }.getOrDefault("<không đọc được dạng text, có thể là binary>")
            Log.d(TAG, "loadSingleStream: server=${stream.server_name} PREFLIGHT url=$url -> HTTP code=${preflight.code} Content-Type=$contentType, 200 ký tự đầu: $bodyPreview")
            if (!bodyPreview.trimStart().startsWith("#EXTM3U")) {
                Log.w(TAG, "loadSingleStream: server=${stream.server_name} PREFLIGHT CẢNH BÁO - response KHÔNG bắt đầu bằng '#EXTM3U', có thể không phải m3u8 hợp lệ -> nguy cơ player lỗi 'Cannot find sync byte'")
            }

            // Gom toàn bộ Set-Cookie trả về (có thể nhiều dòng, mỗi dòng 1 cookie) thành
            // 1 header "Cookie: name1=val1; name2=val2" chuẩn để gửi lại. Dùng
            // preflight.okhttpResponse (property chuẩn của NiceResponse trong Cloudstream
            // trỏ tới okhttp3.Response gốc) để chắc chắn có .headers.values("Set-Cookie")
            // đúng kiểu okhttp3.Headers — tránh phụ thuộc vào wrapper Headers riêng của
            // Cloudstream (nếu preflight.headers là wrapper, nó có thể không hỗ trợ
            // values(), chỉ hỗ trợ operator get() trả về 1 giá trị đầu tiên).
            val setCookies = runCatching {
                preflight.okhttpResponse.headers.values("Set-Cookie")
            }.getOrDefault(emptyList())
            if (setCookies.isNotEmpty()) {
                cookieHeader = setCookies.joinToString("; ") { it.substringBefore(";") }
                Log.d(TAG, "loadSingleStream: server=${stream.server_name} nhận được ${setCookies.size} Set-Cookie từ preflight -> cookieHeader=$cookieHeader")
            } else {
                Log.d(TAG, "loadSingleStream: server=${stream.server_name} preflight KHÔNG có Set-Cookie nào")
            }
        }, onError = { e ->
            Log.w(TAG, "loadSingleStream: server=${stream.server_name} PREFLIGHT LỖI khi kiểm tra url=$url: ${e.message}")
        })

        if (cookieHeader != null) {
            headers["Cookie"] = cookieHeader as String
            Log.d(TAG, "loadSingleStream: server=${stream.server_name} đã gắn header Cookie vào headers cuối cùng gửi cho player: $cookieHeader")
        }

        // SỬA LỖI (structured concurrency + thiếu log lỗi FE): trước đây đoạn này
        // không có try/catch riêng, nên nếu newExtractorLink()/callback() ném lỗi, nó
        // bay thẳng lên catchNonCancellation() ở loadEpisodeStreams() và bị gộp chung
        // vào log "episodeId=... LỖI", không biết được cụ thể server FE nào là thủ
        // phạm (đặc biệt hại khi 1 episode có nhiều server chạy song song). Bọc riêng
        // bằng catchNonCancellation() giống nhánh HY để log rõ server + giữ nguyên tín
        // hiệu hủy (timeout/sibling lỗi) thay vì nuốt mất.
        val feLoaded = catchNonCancellation({
            val link = newExtractorLink(name, stream.server_name ?: name, url, ExtractorLinkType.M3U8) {
                this.referer = referer
                this.headers = headers
                this.quality = Qualities.Unknown.value
            }

            Log.d(TAG, "loadSingleStream: server=${stream.server_name} link M3U8 trực tiếp, gửi callback")
            callback(link)
            true
        }, onError = { e ->
            Log.e(TAG, "loadSingleStream: server=${stream.server_name} FE LỖI: ${e.message}", e)
            false // bỏ qua lỗi riêng của server FE này, không chặn các server khác
        })

        if (feLoaded) loaded.set(true)
        forwardSubtitles()
        return feLoaded
    }

    /**
     * LƯU Ý: Class ẩn danh gốc "Anime47Provider$getVideoInterceptor$1" (triển khai Interceptor)
     * KHÔNG có trong file .cs3 / bản decompile được cung cấp, nên phần dưới đây được suy luận
     * hợp lý từ tên hàm findMpegTsOffset() và regex domain, không phải dịch chính xác 100% từ bytecode gốc.
     * Vui lòng kiểm tra và điều chỉnh lại nếu bạn có bản gốc chính xác hơn.
     */
    override fun getVideoInterceptor(extractorLink: ExtractorLink): Interceptor? {
        // Link Hydrax/Abyss trỏ về host relay nội bộ (xem HydraxExtractor.buildRelayUrl);
        // mọi request Range của player phải đi qua HydraxInterceptor để dịch sang giao thức
        // segment-token thật của Abyss. Không chạm vào logic CDN nonprofit.asia bên dưới.
        if (extractorLink.url.contains(HydraxExtractor.RELAY_HOST)) {
            return HydraxInterceptor
        }

        // HIỆU NĂNG: regex/interceptor CDN "nonprofit.asia" chỉ thực sự cần thiết cho các
        // link không phải Hydrax. Dùng cdnFixRegex ở cấp companion (biên dịch 1 lần duy
        // nhất khi class được load) thay vì tạo Regex mới mỗi lần getVideoInterceptor()
        // được gọi (tức mỗi ExtractorLink của mỗi tập/mỗi server) — tránh chi phí compile
        // regex lặp lại không cần thiết.
        return Interceptor { chain ->
            var request = chain.request()

            // SỬA LỖI (root cause thật sự của "Sorry, you have been blocked" trên CDN
            // segment): loadSingleStream() gắn cứng header "authority" = host của
            // pl.vlogphim.net (domain playlist gốc) + "Origin" = referer vào toàn bộ
            // ExtractorLink. Cloudstream/OkHttp áp các header này cho MỌI request phái
            // sinh từ cùng player session, kể cả các request tới segment nằm trên domain
            // HOÀN TOÀN KHÁC (cdn4.nonprofit.asia, cdn6.nonprofit.asia...) được liệt kê
            // bên trong sub-playlist m3u8. Hệ quả: request tới CDN segment mang header
            // "authority: pl.vlogphim.net" không khớp Host thật (nonprofit.asia) — bị
            // Cloudflare trên CDN đó coi là request giả mạo/bất thường và trả về trang
            // chặn "Sorry, you have been blocked" (đã xác nhận qua ảnh chụp thực tế),
            // với Content-Type bị đội lốt "image/png" khiến trước đây bị hiểu lầm là ảnh
            // PNG thật. Sửa: nếu host thật của request KHÁC domain mà header
            // "authority"/"Origin" đang trỏ tới, loại bỏ 2 header đó (để OkHttp tự set
            // đúng theo Host thật) trước khi cho request đi tiếp.
            val requestHost = request.url.host
            val authorityHeader = request.header("authority")
            if (authorityHeader != null && !authorityHeader.equals(requestHost, ignoreCase = true)) {
                Log.d(TAG, "getVideoInterceptor: request tới host=$requestHost nhưng header 'authority' đang trỏ sai sang '$authorityHeader' -> loại bỏ header authority/Origin lệch domain")
                request = request.newBuilder()
                    .removeHeader("authority")
                    .removeHeader("Origin")
                    .build()
            }

            val response = chain.proceed(request)
            val requestUrl = request.url.toString()

            // CHẨN ĐOÁN (log tổng quát): trước đây interceptor chỉ log khi request khớp
            // cdnFixRegex (domain "nonprofit.asia"), nên nếu segment video thật sự nằm
            // trên MỘT DOMAIN KHÁC (vd. chính pl.vlogphim.net khi resolve URL tương đối
            // "/m3u8/<hash>/<token>" từ master playlist), request đó lọt qua hoàn toàn
            // không để lại log nào — trông như "im lặng" dù player vẫn đang gọi mạng thật.
            // Log 1 dòng ngắn cho MỌI request đi qua interceptor này (không lọc domain)
            // để luôn thấy được domain/host thật ExoPlayer đang gọi khi phát, tách biệt
            // khỏi khối xử lý "fix" bên dưới (vẫn chỉ chạy cho nonprofit.asia như cũ).
            Log.d(TAG, "getVideoInterceptor: request qua đây -> host=${request.url.host} path=${request.url.encodedPath} HTTP code=${response.code} Content-Type=${response.header("Content-Type")}")

            // CHẨN ĐOÁN (nội dung thật của playlist): log ở trên chỉ cho biết HTTP code
            // và Content-Type từ HEADER — không đảm bảo BODY thật sự là m3u8 hợp lệ. Log
            // thực tế cho thấy ExoPlayer báo "ERROR_CODE_PARSING_CONTAINER_MALFORMED" +
            // "Lỗi mã hóa" ngay sau khi tải xong 1 sub-playlist "/m3u8/<hash>/<token2>"
            // (token khác với sub-playlist đầu tiên đã load OK trước đó — nhiều khả năng
            // là bitrate/resolution thứ 2 trong danh sách adaptive), dù response header
            // vẫn báo 200 + đúng Content-Type. Peek (đọc không tiêu thụ, không ảnh hưởng
            // luồng dữ liệu ExoPlayer sẽ đọc sau) một đoạn ngắn ở đầu body để xem nội
            // dung thật — phân biệt được các case: m3u8 hợp lệ thật (bắt đầu #EXTM3U),
            // trang lỗi/HTML, JSON báo lỗi từ CDN, hoặc body rỗng/mã hoá lạ.
            val contentType = response.header("Content-Type") ?: ""
            if (contentType.contains("mpegurl", ignoreCase = true) || requestUrl.contains("/m3u8/")) {
                val previewBody = response.body
                if (previewBody != null) {
                    try {
                        val peekedSource = previewBody.source().peek()
                        val previewBuffer = Buffer()
                        peekedSource.read(previewBuffer, 300L)
                        val previewText = runCatching { previewBuffer.readString(Charsets.UTF_8) }
                            .getOrDefault("<không decode được UTF-8, có thể là binary>")
                        Log.d(TAG, "getVideoInterceptor: url=$requestUrl NỘI DUNG playlist (300 ký tự đầu): $previewText")
                    } catch (e: Exception) {
                        Log.w(TAG, "getVideoInterceptor: url=$requestUrl không peek được nội dung body: ${e.message}")
                    }
                } else {
                    Log.w(TAG, "getVideoInterceptor: url=$requestUrl response.body() null, không có gì để peek")
                }
            }

            // ĐÍNH CHÍNH LẦN 2 (dựa trên bằng chứng mới nhất): log playlist đầy đủ xác
            // nhận TOÀN BỘ segment trong sub-playlist — không ngoại lệ, trên MỌI CDN con
            // (cdn1..cdn6) — đều dùng path "/img/...". Không có bất kỳ segment nào dùng
            // path khác ("/video/", "/ts/", đuôi .ts...). Điều này cho thấy "/img/" là
            // QUY ƯỚC PATH THẬT của CDN nonprofit.asia cho segment media (kỹ thuật giấu
            // định dạng thật để né hotlink/bot), KHÔNG PHẢI dấu hiệu để phân biệt
            // ảnh-thật-vs-segment-giả như 2 lần sửa trước đã giả định nhầm. Giả thuyết
            // "PNG thật" trước đó dựa trên việc mở link KHÔNG kèm Referer trên trình
            // duyệt và thấy trang chặn Cloudflare "Sorry, you have been blocked" — nhưng
            // trang chặn đó CŨNG trả Content-Type: image/png, nên không thể dùng để kết
            // luận nội dung thật của response khi app gọi (CÓ Referer/header đầy đủ) là
            // gì. Khôi phục xử lý cho path "/img/" (bỏ loại trừ) để tìm sync-byte MPEG-TS
            // như logic gốc — đồng thời thêm log dump nhiều byte + kiểm tra dấu hiệu HTML
            // (trang chặn) để phân biệt rạch ròi 3 khả năng: (a) segment TS giả trang
            // PNG hợp lệ -> cắt offset, (b) trang chặn Cloudflare giả dạng PNG -> log rõ
            // để biết cần xử lý Cloudflare challenge, (c) ảnh PNG thật khác không liên
            // quan -> giữ nguyên.
            if (!cdnFixRegex.containsMatchIn(requestUrl)) {
                return@Interceptor response
            }

            Log.d(TAG, "getVideoInterceptor: nonprofit.asia CDN khớp regex, url=$requestUrl HTTP code=${response.code} Content-Type=${response.header("Content-Type")} Content-Length=${response.header("Content-Length")}")

            val body = response.body
            if (body == null) {
                Log.w(TAG, "getVideoInterceptor: nonprofit.asia url=$requestUrl response.body() null, trả nguyên response gốc")
                return@Interceptor response
            }

            try {
                // HIỆU NĂNG (real fix): bản trước gọi body.bytes() — tải TOÀN BỘ segment/
                // file vào RAM chỉ để cắt bỏ vài byte rác ở đầu (offset đồng bộ MPEG-TS),
                // rồi mới trả cho player. Với các CDN nonprofit.asia phục vụ file lớn (vài
                // chục MB trở lên), điều này vừa tốn RAM vừa làm player phải chờ tải xong
                // 100% mới bắt đầu decode — triệt tiêu hoàn toàn lợi ích của streaming
                // (đúng vấn đề mà HydraxInterceptor.SegmentSource ở trên đã xử lý). Sửa:
                // chỉ "peek" (đọc không tiêu thụ) một cửa sổ nhỏ ở đầu source để tìm offset,
                // sau đó skip() đúng số byte rác đó trên source thật rồi trả thẳng phần
                // source còn lại (chưa đọc) cho player — dữ liệu được stream liên tục,
                // không buffer toàn bộ vào bộ nhớ.
                val source = body.source()
                val peeked = source.peek()
                val headerBuffer = Buffer()
                var peekedBytes = 0L
                while (peekedBytes < TS_SYNC_PEEK_BYTES) {
                    val read = peeked.read(headerBuffer, TS_SYNC_PEEK_BYTES - peekedBytes)
                    if (read == -1L) break
                    peekedBytes += read
                }

                val peekedHex = headerBuffer.snapshot().let { snapshot ->
                    (0 until minOf(16, snapshot.size)).joinToString(" ") { "%02x".format(snapshot[it]) }
                }
                val offset = findMpegTsOffset(headerBuffer.readByteArray())
                Log.d(TAG, "getVideoInterceptor: nonprofit.asia url=$requestUrl đã peek $peekedBytes byte, 16 byte hex đầu=[$peekedHex], offset đồng bộ tìm được=$offset")
                if (offset <= 0) {
                    // CHẨN ĐOÁN (phân biệt PNG thật/segment giả trang PNG với trang chặn
                    // Cloudflare): cả 3 loại nội dung đều có thể mang Content-Type:
                    // image/png và bắt đầu bằng magic bytes PNG hợp lệ (Cloudflare có thể
                    // trả trang chặn dưới dạng ảnh render sẵn). Không tìm thấy offset
                    // MPEG-TS ở 16 byte đầu KHÔNG loại trừ khả năng đây là segment giả
                    // trang PNG thật (payload TS có thể nằm sau một đoạn PNG "vỏ bọc" dài
                    // hơn cửa sổ peek hiện tại, hoặc bị bọc thêm 1 lớp khác). Thử tìm dấu
                    // hiệu text của trang chặn Cloudflare ("cloudflare", "blocked",
                    // "sorry") ở dạng ISO-8859-1 (an toàn cho binary) trong toàn bộ cửa sổ
                    // đã peek, để phân biệt rõ 2 khả năng còn lại: (a) đây thực sự là
                    // trang chặn Cloudflare -> cần retry qua CloudflareKiller/WebView;
                    // (b) đây là ảnh/segment khác không phải TS -> không có gì để sửa.
                    val fullPeekedBytes = run {
                        val rediagBuffer = Buffer()
                        val rediagPeek = source.peek()
                        var n = 0L
                        while (n < TS_SYNC_PEEK_BYTES) {
                            val r = rediagPeek.read(rediagBuffer, TS_SYNC_PEEK_BYTES - n)
                            if (r == -1L) break
                            n += r
                        }
                        rediagBuffer.readByteArray()
                    }
                    val asIso = String(fullPeekedBytes, Charsets.ISO_8859_1)
                    val looksLikeCloudflareBlock = listOf("cloudflare", "sorry, you have been blocked", "blocked", "<html").any {
                        asIso.contains(it, ignoreCase = true)
                    }
                    if (looksLikeCloudflareBlock) {
                        Log.e(TAG, "getVideoInterceptor: nonprofit.asia url=$requestUrl NGHI VẤN đây là TRANG CHẶN CLOUDFLARE giả dạng Content-Type image/png (tìm thấy chuỗi 'cloudflare'/'blocked'/'<html' trong $peekedBytes byte đầu) -> KHÔNG PHẢI segment video thật, cần xử lý challenge Cloudflare thay vì tìm sync-byte")
                    } else {
                        Log.w(TAG, "getVideoInterceptor: nonprofit.asia url=$requestUrl KHÔNG tìm thấy byte đồng bộ MPEG-TS (0x47) trong $peekedBytes byte đầu, cũng KHÔNG có dấu hiệu trang chặn Cloudflare -> có thể là ảnh/segment không xác định, giữ nguyên response")
                    }
                } else {
                    source.skip(offset.toLong())
                }

                val originalLength = body.contentLength()
                val fixedLength = if (offset > 0 && originalLength >= 0) originalLength - offset else originalLength

                val fixedBody = object : ResponseBody() {
                    override fun contentType() = body.contentType()
                    override fun contentLength() = fixedLength
                    override fun source() = source
                }

                val responseBuilder = response.newBuilder().body(fixedBody)
                // Đồng bộ header Content-Length với body thật sự trả về — tránh lệch giữa
                // header (vẫn phản ánh kích thước gốc từ server) và dữ liệu thật (đã bị cắt
                // bớt `offset` byte), có thể khiến client HTTP nghiêm ngặt xử lý sai/cắt cụt.
                if (offset > 0) {
                    if (fixedLength >= 0) {
                        responseBuilder.header("Content-Length", fixedLength.toString())
                    } else {
                        responseBuilder.removeHeader("Content-Length")
                    }
                }
                responseBuilder.build()
            } catch (e: IOException) {
                // Đọc/skip source thất bại giữa chừng (mạng gián đoạn): trả lỗi gốc cho
                // player xử lý (retry/next server) thay vì làm crash luồng phát video.
                Log.e(TAG, "getVideoInterceptor: nonprofit.asia url=$requestUrl IOException khi đọc/skip source: ${e.message}", e)
                response
            }
        }
    }

    // SỬA LỖI (build): Kotlin chỉ cho phép 1 companion object mỗi class — trước đây có
    // 2 khai báo "companion object" tách biệt (1 ẩn danh cho cdnFixRegex, 1 tên
    // "Session" cho sharedCachedToken) trong cùng file, đây là lỗi biên dịch. Gộp lại
    // thành 1 companion object "Session" duy nhất chứa cả hai.
    companion object Session {
        // Ngân sách thời gian tối đa cho toàn bộ 1 episode (watch-info + mọi server song
        // song). Đủ rộng cho trường hợp xấu nhất: watch-info (WATCH_INFO_TIMEOUT_MS) rồi
        // TUẦN TỰ 2 lần gọi embed Hydrax (mỗi lần tối đa HydraxExtractor.HY_EMBED_TIMEOUT_MS,
        // xem ghi chú tại loadLinks()) cộng dư ~2s cho các bước xử lý CPU (decrypt/parse).
        // 15s + 8s + 8s + 2s dư = 33s -> làm tròn lên 35s để không cắt oan các trường hợp
        // hợp lệ nhưng chậm, trong khi vẫn đủ chặt để không treo vô hạn khi 1 server thật
        // sự bị treo.
        const val EPISODE_TIMEOUT_MS = 35_000L

        // Biên dịch 1 lần duy nhất cho toàn bộ vòng đời class thay vì mỗi lần gọi
        // getVideoInterceptor().
        private val cdnFixRegex = Regex("nonprofit\\.asia|cdn\\d+\\.nonprofit")

        // Cửa sổ "peek" đủ rộng (~32 gói TS = ~6KB) để tìm byte đồng bộ MPEG-TS (0x47)
        // mà không cần đọc toàn bộ file — phần rác thường chỉ nằm ở vài trăm byte đầu.
        private const val TS_SYNC_PEEK_BYTES = 188L * 32

        // HIỆU NĂNG: biên dịch 1 lần duy nhất thay vì mỗi lần gọi load() (tức mỗi lần
        // người dùng mở 1 trang chi tiết phim).
        private val animeIdRegex = Regex("(\\d+)(?:\\.html|/)?$")

        // Dùng chung cho mọi instance (Cloudstream chỉ tạo 1 instance provider trong
        // thực tế), cho phép Settings vô hiệu hoá token hiện tại mà không cần giữ tham
        // chiếu tới provider — xem ghi chú đầy đủ tại khai báo "cachedToken" ở trên.
        val sharedCachedToken = java.util.concurrent.atomic.AtomicReference<String?>(null)

        /** Gọi khi người dùng xoá thông tin đăng nhập từ màn hình cài đặt. */
        fun invalidateCachedSession() {
            sharedCachedToken.set(null)
        }
    }
    // ===================== Data classes (API models) =====================

    data class LoginRequest(
        val login: String,
        val password: String
    )

    data class LoginResponse(
        val access_token: String?,
        val refresh_token: String?
    )

    data class GenreInfo(
        val name: String?
    )

    data class CharacterInfo(
        val name: String?,
        val role: String?,
        val image_url: String?
    )

    data class Post(
        val id: Int,
        val title: String,
        val slug: String,
        val link: String,
        val poster: String?,
        val episodes: String?,
        val current_episode: String?,
        val type: String?,
        val year: String?
    )

    data class ApiFilterData(
        val posts: List<Post>? = null
    )

    data class ApiFilterResponse(
        val success: Boolean? = null,
        val message: String? = null,
        val data: ApiFilterData? = null
    )

    data class VideoItem(
        val url: String?
    )

    data class DetailPost(
        val id: Int,
        val title: String?,
        val description: String?,
        val poster: String?,
        val cover: String?,
        val type: String?,
        val year: String?,
        val genres: List<GenreInfo>?,
        val videos: List<VideoItem>?,
        val score: Double?,
        val characters: List<CharacterInfo>?
    )

    data class ApiDetailResponse(
        val data: DetailPost
    )

    data class EpisodeListItem(
        val id: Int,
        val number: Int?,
        val title: String?
    )

    data class EpisodeGroup(
        val name: String?,
        val episodes: List<EpisodeListItem>
    )

    data class EpisodeTeam(
        val team_name: String?,
        val groups: List<EpisodeGroup>
    )

    data class ApiEpisodeResponse(
        val teams: List<EpisodeTeam>
    )

    data class SubtitleItem(
        val file: String?,
        val label: String?
    )

    data class Stream(
        val url: String?,
        val server_name: String?,
        val player_type: String?,
        val subtitles: List<SubtitleItem>?
    )

    data class WatchAnimeInfo(
        val id: Int,
        val title: String?,
        val slug: String?,
        val thumbnail: String?
    )

    data class ApiWatchResponse(
        val id: Int?,
        val streams: List<Stream>?,
        val anime: WatchAnimeInfo?
    )

    data class RecommendationItem(
        val id: Int,
        val title: String?,
        val link: String?,
        val poster: String?,
        val type: String?,
        val year: String?,
        val episodes: String?,
        val current_episode: String?
    )

    data class ApiRecommendationResponse(
        val data: List<RecommendationItem>?
    )

    data class SearchItem(
        val id: Int,
        val title: String,
        val link: String,
        val image: String?,
        val type: String?,
        val episodes: String?,
        val current_episode: String?
    )

    data class ApiSearchResponse(
        val results: List<SearchItem>?,
        val has_more: Boolean?
    )
}
