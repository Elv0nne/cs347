package recloudstream

import android.content.Context
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.lagradost.cloudstream3.plugins.CloudstreamPlugin
import com.lagradost.cloudstream3.plugins.Plugin

@CloudstreamPlugin
class Anime47Plugin : Plugin() {

    // SỬA LỖI (dọn dẹp): hàm verifySignature() trước đây được định nghĩa nhưng KHÔNG
    // bao giờ được gọi ở bất kỳ đâu trong plugin (dead code) — không hề có tác dụng bảo
    // mật thực tế nào vì không được dùng để chặn/allow bất cứ điều gì trong load(). Giữ
    // nó lại chỉ gây hiểu nhầm là plugin có xác thực chữ ký APK trong khi thực chất
    // không có. Xoá bỏ để giảm code không dùng tới; nếu cần bật lại tính năng kiểm tra
    // chữ ký, hãy khôi phục kèm theo lệnh gọi thực sự trong load().
    override fun load(context: Context) {
        // Trực tiếp khởi tạo và đăng ký API
        val provider = Anime47Provider()
        registerMainAPI(provider)

        // Cài đặt setting
        this.openSettings = { ctx ->
            val activity = ctx as? AppCompatActivity
            if (activity != null) {
                Anime47SettingsDialog().show(activity.supportFragmentManager, "Anime47Settings")
            } else {
                Toast.makeText(ctx, "Lỗi: Không thể khởi tạo giao diện cài đặt", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
