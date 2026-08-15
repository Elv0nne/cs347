// build.gradle.kts mẫu — dựa theo cấu trúc chuẩn của một CloudStream provider plugin.
// File này KHÔNG được trích xuất từ .cs3 gốc (file .cs3 chỉ chứa .dex đã biên dịch),
// mà được viết lại theo template phổ biến của các plugin CloudStream khác để bạn có thể
// build lại project. Hãy đối chiếu với repo mẫu (ví dụ CloudstreamExtensions) và điều
// chỉnh version/dependency nếu cần.

version = 14 // trùng với "version" trong manifest.json gốc

cloudstream {
    // Mô tả hiển thị trong app CloudStream
    language = "vi"
    description = "Anime47 - Xem anime vietsub/thuyết minh"
    authors = listOf("H4RS")

    /**
     * Trạng thái:
     * 0: Xuống cấp/Không hoạt động
     * 1: Ổn định
     * 2: Đang phát triển/Beta
     * 3: Chỉ dành cho mạng nội bộ (localhost)
     */
    status = 1

    tvTypes = listOf("Anime", "Cartoon")

    iconUrl = "https://anime47.best/favicon.ico"
}

android {
    defaultConfig {
        minSdk = 21
    }
}

dependencies {
       implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
       implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
       implementation("androidx.preference:preference-ktx:1.2.1")
       implementation("androidx.appcompat:appcompat:1.6.1")
       implementation("androidx.fragment:fragment-ktx:1.6.2")
}
