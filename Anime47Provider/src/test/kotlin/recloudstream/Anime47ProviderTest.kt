package recloudstream

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit test cho phần logic THUẦN (không đụng network/Android) của Anime47Provider —
 * cụ thể là findMpegTsOffset(), hàm quyết định "cắt bao nhiêu byte vỏ bọc PNG giả"
 * trước khi trả segment cho ExoPlayer trong getVideoInterceptor().
 *
 * MỤC ĐÍCH: đây là hàm dễ vỡ nhất nếu CDN nonprofit.asia đổi cách bọc segment (đã từng
 * xảy ra 1 lần — xem ghi chú TS_SYNC_PEEK_BYTES trong Anime47Provider.kt, offset cố định
 * quan sát được là 22610 byte). Test này không gọi mạng thật; nó chỉ đảm bảo hàm tìm
 * đúng offset với dữ liệu MPEG-TS giả lập có cấu trúc known-good/known-bad, để mỗi khi
 * sửa hàm (hoặc nghi ngờ nó là nguyên nhân lỗi mới) có thể chạy `./gradlew test` thay vì
 * phải cài app thật lên máy và xem logcat.
 *
 * CHẠY: từ thư mục gốc repo — `./gradlew :Anime47Provider:test`
 * (cần thêm testImplementation("junit:junit:4.13.2") vào Anime47Provider/build.gradle.kts
 * nếu chưa có — xem ghi chú cuối file.)
 */
class Anime47ProviderTest {

    // findMpegTsOffset là hàm internal của Anime47Provider (đã đổi từ private -> internal
    // để test được), nên cần 1 instance của provider. Cloudstream's MainAPI có thể yêu cầu
    // Android context để khởi tạo đầy đủ; nếu constructor mặc định không chạy được trong
    // JVM test thuần (lỗi liên quan tới android.util.Log hoặc SharedPreferences), xem ghi
    // chú "MOCKING ANDROID" ở cuối file — cách đơn giản nhất là mock android.util.Log qua
    // Robolectric hoặc chuyển hàm ra ngoài thành top-level function không phụ thuộc class.
    private val provider = Anime47Provider()

    private fun tsPacket(syncByte: Byte = 0x47): ByteArray = ByteArray(188).also { it[0] = syncByte }

    private fun buildValidTsAt(offset: Int, packetCount: Int = 3, totalSize: Int = offset + 188 * packetCount): ByteArray {
        val data = ByteArray(totalSize) { 0x00 }
        for (p in 0 until packetCount) {
            val pos = offset + p * 188
            if (pos < totalSize) data[pos] = 0x47
        }
        return data
    }

    @Test
    fun `offset 0 khi TS bat dau ngay tu dau, khong co vo boc`() {
        val data = buildValidTsAt(offset = 0)
        assertEquals(0, provider.findMpegTsOffset(data))
    }

    @Test
    fun `tim dung offset 22610 - gia tri thuc te da quan sat tren CDN nonprofit-asia`() {
        val data = buildValidTsAt(offset = 22610, totalSize = 22610 + 188 * 5)
        assertEquals(22610, provider.findMpegTsOffset(data))
    }

    @Test
    fun `tra ve -1 khi khong co byte dong bo 0x47 lien tiep 3 lan`() {
        val data = ByteArray(65536) { 0x00 }
        assertEquals(-1, provider.findMpegTsOffset(data))
    }

    @Test
    fun `tra ve -1 khi co byte 0x47 don le nhung khong lap lai dung 188 byte`() {
        // 0x47 xuất hiện nhưng không có 2 gói kế tiếp cách đúng 188 byte -> không được
        // tính là sync thật, tránh false positive trên dữ liệu ngẫu nhiên trùng hợp.
        val data = ByteArray(1000) { 0x00 }
        data[100] = 0x47
        data[150] = 0x47 // sai khoảng cách (không phải 188)
        assertEquals(-1, provider.findMpegTsOffset(data))
    }

    @Test
    fun `du lieu qua ngan hon 3 goi TS luon tra ve -1`() {
        val data = ByteArray(188 * 3 - 1) { 0x47 }
        assertEquals(-1, provider.findMpegTsOffset(data))
    }

    @Test
    fun `khong bi off-by-one o vi tri cuoi cung con du cho 3 goi`() {
        // Trường hợp biên: offset hợp lệ DUY NHẤT nằm ở lastValidIndex = size - minLen.
        // Bug off-by-one gốc (dùng "until" thay vì "..") sẽ bỏ sót đúng vị trí này.
        val minLen = 188 * 3
        val data = buildValidTsAt(offset = 0, totalSize = minLen)
        assertEquals(0, provider.findMpegTsOffset(data))
    }

    @Test
    fun `chon offset dau tien tim thay neu co nhieu vi tri hop le`() {
        val data = ByteArray(188 * 6) { 0x00 }
        // 2 vị trí hợp lệ độc lập: offset 0 và offset 188*3 — hàm phải trả về vị trí SỚM
        // NHẤT (0), không phải vị trí cuối, vì offset càng lớn nghĩa là cắt bỏ càng nhiều
        // dữ liệu thật (không mong muốn).
        for (p in 0 until 6) data[p * 188] = 0x47
        assertEquals(0, provider.findMpegTsOffset(data))
    }

    @Test
    fun `EXPECTED_TS_OFFSET hang so khop voi gia tri da quan sat thuc te`() {
        // Neu ai do sua companion object ma quen cap nhat EXPECTED_TS_OFFSET, test nay se
        // fail va nhac nho — hang so nay dung de StreamHealthStats phat hien khi CDN doi
        // kich thuoc vo boc (xem Anime47Provider.StreamHealthStats.recordOffset).
        assertEquals(22610, Anime47Provider.EXPECTED_TS_OFFSET)
    }

    @Test
    fun `khong bao offset dung neu chi 1 goi dau tien co 0x47 con 2 goi sau bi hong`() {
        // Mô phỏng đúng rủi ro của OFFSET_VERIFY: nếu dữ liệu server trả về có 0x47 tình
        // cờ ở vị trí X nhưng KHÔNG lặp lại đúng 188 byte sau đó 2 lần (segment thật bị
        // hỏng/cắt cụt giữa chừng), findMpegTsOffset phải trả về -1, không được báo "tìm
        // thấy" nhầm chỉ vì gói đầu tiên khớp. Đây là điều kiện mà OFFSET_VERIFY_FAILED
        // trong interceptor bổ sung thêm 1 lớp kiểm tra runtime (test này chỉ xác nhận
        // phần logic offset-finding không tự tin nhầm).
        val data = ByteArray(188 * 5) { 0x00 }
        data[10] = 0x47 // gói "đầu tiên" trông giống hợp lệ...
        data[10 + 188] = 0x00 // ...nhưng gói kế tiếp SAI -> không phải TS thật
        assertEquals(-1, provider.findMpegTsOffset(data))
    }
}

/*
 * GHI CHÚ THIẾT LẬP (nếu module chưa có JUnit / chưa chạy được test):
 *
 * 1) Thêm dependency test vào Anime47Provider/build.gradle.kts:
 *
 *      dependencies {
 *          // ... các dependency hiện có ...
 *          testImplementation("junit:junit:4.13.2")
 *      }
 *
 * 2) Chạy: ./gradlew :Anime47Provider:test
 *    Báo cáo HTML nằm ở Anime47Provider/build/reports/tests/test/index.html
 *
 * MOCKING ANDROID: nếu Anime47Provider() không khởi tạo được trong JVM test thuần (ví dụ
 * lỗi "Method d in android.util.Log not mocked"), 2 hướng xử lý:
 *   a) Thêm Robolectric (testImplementation("org.robolectric:robolectric:4.11.1") +
 *      @RunWith(RobolectricTestRunner::class) trên class test) để có môi trường Android
 *      giả lập đầy đủ trong JVM.
 *   b) Đơn giản hơn cho riêng hàm này: tách findMpegTsOffset() ra thành một top-level
 *      function độc lập (không phải method của class Anime47Provider) trong cùng file
 *      hoặc file util riêng — vì bản thân hàm không dùng bất kỳ API Android nào, chỉ thao
 *      tác ByteArray thuần túy, nên tách ra sẽ test được ngay không cần mock gì cả.
 */
