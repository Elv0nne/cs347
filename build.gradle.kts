import com.android.build.gradle.BaseExtension
import com.lagradost.cloudstream3.gradle.CloudstreamExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile
import java.net.URI
import java.net.HttpURLConnection

// TỰ ĐỘNG LẤY COMMIT HASH CỦA TAG "manual-1" (bản release chính thức đã publish
// trên repo Elv0nne/cloudstream, thay vì "pre-release" như trước).
// Lý do: overrideUrlPrefix() bên dưới tải classes.jar (dùng lúc RUNTIME) theo TAG
// "manual-1". Nếu coordinate JitPack (dùng để compile stub) bị hardcode một hash cũ
// hoặc lệch tag, plugin sẽ build lệch khỏi app thật đang chạy -> lỗi hàng loạt.
// Gọi GitHub API ngay tại thời điểm build để lấy ĐÚNG commit mà tag đang trỏ tới,
// đảm bảo compile-time stub và runtime classes.jar luôn khớp nhau tự động.
fun resolveReleaseCommitHash(): String {
    val fallback = "38c51e8" // dùng nếu API lỗi/rate-limit, tránh build fail hoàn toàn
    return try {
        val url = URI("https://api.github.com/repos/Elv0nne/cloudstream/git/ref/tags/manual-1").toURL()
        val conn = url.openConnection() as HttpURLConnection
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        conn.connectTimeout = 10_000
        conn.readTimeout = 10_000
        val text = conn.inputStream.bufferedReader().readText()
        // Tag "manual-1" là lightweight tag -> object.sha ở ref API CHÍNH LÀ commit
        // hash luôn (không phải annotated tag object cần thêm 1 lượt gọi resolve nữa).
        val sha = Regex("\"sha\"\\s*:\\s*\"([0-9a-f]{7,40})\"").find(text)?.groupValues?.get(1)
        (sha?.take(7) ?: fallback).also {
            logger.lifecycle("[Anime47Provider] resolved manual-1 commit = $it")
        }
    } catch (e: Exception) {
        logger.warn("[Anime47Provider] Không lấy được commit hash manual-1 qua API (${e.message}), dùng fallback=$fallback. " +
            "Nếu app trên máy KHÔNG phải build từ commit $fallback, hãy build lại khi có mạng để tự động khớp đúng bản.")
        fallback
    }
}

val releaseCommitHash = resolveReleaseCommitHash()

buildscript {
    repositories {
        google()
        mavenCentral()
        // Shitpack repo which contains our tools and dependencies
        maven("https://jitpack.io")
    }

    dependencies {
        classpath("com.android.tools.build:gradle:8.7.3")
        // Cloudstream gradle plugin which makes everything work and builds plugins
        classpath("com.github.recloudstream:gradle:-SNAPSHOT")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.3.0")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}

fun Project.cloudstream(configuration: CloudstreamExtension.() -> Unit) = extensions.getByName<CloudstreamExtension>("cloudstream").configuration()

fun Project.android(configuration: BaseExtension.() -> Unit) = extensions.getByName<BaseExtension>("android").configuration()

subprojects {
    apply(plugin = "com.android.library")
    apply(plugin = "kotlin-android")
    apply(plugin = "com.lagradost.cloudstream3.gradle")

    cloudstream {
        // when running through github workflow, GITHUB_REPOSITORY should contain current repository name
        setRepo(System.getenv("GITHUB_REPOSITORY") ?: "Elv0nne/uhnimefourseven")

        // overrideUrlPrefix() ghi đè urlPrefix mặc định (luôn trỏ về repo GỐC
        // recloudstream/cloudstream), trỏ sang GitHub Release thật của fork
        // Elv0nne/cloudstream — release này đã tồn tại với tag "manual-1" (commit
        // 38c51e8, khác với tag di động "pre-release"). Kết quả: plugin sẽ tải
        // "https://github.com/Elv0nne/cloudstream/releases/download/manual-1/classes.jar"
        // — ĐÚNG bản release ổn định đã patch WatchProgressListener.
        //
        // LƯU Ý: nếu sau này bạn tạo release mới thay thế "manual-1" (ví dụ
        // "manual-2"), nhớ cập nhật cả 3 chỗ dùng tag này trong file (endpoint GitHub
        // API resolveReleaseCommitHash(), overrideUrlPrefix() ở đây, và coordinate
        // JitPack bên dưới) để tránh lệch giữa compile-time stub và runtime
        // classes.jar.
        overrideUrlPrefix("https://github.com/Elv0nne/cloudstream/releases/download/manual-1")
    }

    android {
        namespace = "com.example"

        defaultConfig {
            minSdk = 21
            compileSdkVersion(35)
            targetSdk = 35
        }

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_1_8
            targetCompatibility = JavaVersion.VERSION_1_8
        }

        tasks.withType<KotlinJvmCompile> {
            compilerOptions {
                jvmTarget.set(JvmTarget.JVM_1_8) // Required
                freeCompilerArgs.addAll(
                    "-Xno-call-assertions",
                    "-Xno-param-assertions",
                    "-Xno-receiver-assertions"
                )
            }
        }
    }

    dependencies {
        val cloudstream by configurations
        val implementation by configurations

        // Stubs for all cloudstream classes.
        // Dùng bản fork đã patch (thêm WatchProgressListener vào MainAPI.kt +
        // forward vị trí phát thật trong GeneratorPlayer.kt) vì bản chính thức
        // KHÔNG có interface WatchProgressListener nên biên dịch sẽ lỗi
        // "Unresolved reference 'WatchProgressListener'".
        //
        // TỰ ĐỘNG: dùng đúng commit mà tag "manual-1" đang trỏ tới NGAY LÚC build này
        // chạy (xem resolveReleaseCommitHash() ở đầu file) — không hardcode tay, nên
        // compile-time stub và runtime classes.jar (tải qua overrideUrlPrefix ở trên,
        // cũng theo tag "manual-1") luôn tự khớp nhau.
        //
        // Đã xác nhận qua JitPack build log
        // (https://jitpack.io/com/github/Elv0nne/cloudstream/manual-1/build.log):
        // coordinate build cho tag "manual-1" tồn tại trên JitPack.
        cloudstream("com.github.Elv0nne.cloudstream:library:$releaseCommitHash")

        // These dependencies can include any of those which are added by the app,
        // but you don't need to include any of them if you don't need them.
        // https://github.com/recloudstream/cloudstream/blob/master/app/build.gradle.kts
        implementation(kotlin("stdlib")) // Adds Standard Kotlin Features
        implementation("com.github.Blatzar:NiceHttp:0.4.11") // HTTP Lib
        implementation("org.jsoup:jsoup:1.18.3") // HTML Parser
        // IMPORTANT: Do not bump Jackson above 2.13.1, as newer versions will
        // break compatibility on older Android devices.
        implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.1") // JSON Parser
    }
}

task<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
} 
