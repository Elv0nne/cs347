import com.android.build.gradle.BaseExtension
import com.lagradost.cloudstream3.gradle.CloudstreamExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile
import java.net.URI
import java.net.HttpURLConnection

// TỰ ĐỘNG LẤY COMMIT HASH CỦA TAG "pre-release" (thay vì hardcode tay như trước).
// Lý do: overrideUrlPrefix() bên dưới tải classes.jar (dùng lúc RUNTIME) theo TAG
// "pre-release", và tag này bị move tới commit mới nhất trên master mỗi lần push
// (xem prerelease.yml). Nếu coordinate JitPack (dùng để compile stub) bị hardcode
// một hash cũ, plugin sẽ build lệch khỏi app thật đang chạy -> lỗi hàng loạt.
// Gọi GitHub API ngay tại thời điểm build để lấy ĐÚNG commit mà tag đang trỏ tới,
// đảm bảo compile-time stub và runtime classes.jar luôn khớp nhau tự động.
fun resolvePreReleaseCommitHash(): String {
    val fallback = "d4b0843" // dùng nếu API lỗi/rate-limit, tránh build fail hoàn toàn
    return try {
        val url = URI("https://api.github.com/repos/Elv0nne/cloudstream/git/ref/tags/pre-release").toURL()
        val conn = url.openConnection() as HttpURLConnection
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        conn.connectTimeout = 10_000
        conn.readTimeout = 10_000
        val text = conn.inputStream.bufferedReader().readText()
        // Tag "pre-release" là lightweight tag -> object.sha ở ref API CHÍNH LÀ commit
        // hash luôn (không phải annotated tag object cần thêm 1 lượt gọi resolve nữa).
        val sha = Regex("\"sha\"\\s*:\\s*\"([0-9a-f]{7,40})\"").find(text)?.groupValues?.get(1)
        (sha?.take(7) ?: fallback).also {
            logger.lifecycle("[Anime47Provider] resolved pre-release commit = $it")
        }
    } catch (e: Exception) {
        logger.warn("[Anime47Provider] Không lấy được commit hash pre-release qua API (${e.message}), dùng fallback=$fallback. " +
            "Nếu app trên máy KHÔNG phải build từ commit $fallback, hãy build lại khi có mạng để tự động khớp đúng bản.")
        fallback
    }
}

val preReleaseCommitHash = resolvePreReleaseCommitHash()

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

        // QUAN TRỌNG: cloudstream Gradle plugin (com.github.recloudstream:gradle) tự
        // tải "cloudstream.jar" (dùng làm compileOnly stub, KHÁC với dependency
        // "cloudstream(...)" khai báo bên dưới trong khối dependencies{}, cái đó chỉ
        // ảnh hưởng tới coordinate JitPack cho phần khác) từ URL HARDCODE trong chính
        // source của plugin:
        //   ApkInfo.urlPrefix mặc định = "https://github.com/recloudstream/cloudstream/releases/download/${version}"
        // (xem CloudstreamExtension.kt + CloudstreamConfigurationProvider.kt trong
        // repo recloudstream/gradle). URL này LUÔN trỏ về repo GỐC
        // recloudstream/cloudstream, bất kể coordinate JitPack mình khai báo là gì —
        // đây là lý do bản build trước lỗi 404 vào
        // ".../recloudstream/cloudstream/releases/download/9b9ae65/classes.jar"
        // (release "9b9ae65" không tồn tại ở repo GỐC, vì đó là commit hash bên FORK
        // của mình).
        //
        // overrideUrlPrefix() ghi đè urlPrefix đó, trỏ sang GitHub Release thật của
        // fork Elv0nne/cloudstream — release này đã tồn tại (workflow "Pre-release"
        // trong fork tự tạo/update GitHub Release tag "pre-release" mỗi lần push lên
        // master, đính kèm đúng file "classes.jar" cần thiết, xem
        // .github/workflows/prerelease.yml). Kết quả: plugin sẽ tải
        // "https://github.com/Elv0nne/cloudstream/releases/download/pre-release/classes.jar"
        // — ĐÚNG bản đã patch WatchProgressListener.
        //
        // LƯU Ý: dùng tag "pre-release" ở đây (khác với commit hash "9b9ae65" dùng
        // cho coordinate JitPack bên dưới) vì GitHub Release attach file theo TAG,
        // không theo commit hash — và workflow luôn move tag "pre-release" tới commit
        // mới nhất trên master mỗi lần push, nên nó tự động theo kịp các patch sau
        // này miễn là bạn đã push code mới lên fork trước khi build plugin.
        overrideUrlPrefix("https://github.com/Elv0nne/cloudstream/releases/download/pre-release")
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
        //
        // ĐÃ SỬA: trỏ sang bản fork đã patch (thêm WatchProgressListener vào
        // MainAPI.kt + forward vị trí phát thật trong GeneratorPlayer.kt) thay vì
        // "com.lagradost:cloudstream3:pre-release" chính thức — bản chính thức
        // KHÔNG có interface WatchProgressListener nên biên dịch sẽ lỗi
        // "Unresolved reference 'WatchProgressListener'".
        //
        // XÁC NHẬN THẬT qua JitPack build log (2026-08-14): coordinate
        // "com.github.Elv0nne.cloudstream:library:9b9ae65" build SUCCESSFUL, publish
        // đúng 3 artifact (library, library-jvm, library-android) — dùng thẳng
        // "library" để Gradle/cloudstream plugin tự chọn đúng variant (android/jvm)
        // theo target đang build, không cần chỉ định hậu tố thủ công.
        //
        // Dùng version cố định là commit hash "9b9ae65" (không dùng tag "pre-release"
        // vì tag đó bị MOVE lại mỗi lần push mới lên Elv0nne/cloudstream, không đảm
        // bảo luôn trỏ đúng bản đã build-verify này). Nếu sau này patch thêm code
        // trên fork, thay "9b9ae65" bằng commit hash mới, rồi tự verify lại qua
        // https://jitpack.io/#Elv0nne/cloudstream/<commit-hash> (bấm "Get it", đợi
        // "BUILD SUCCESSFUL") trước khi build plugin, để tránh build lỗi hoặc dùng
        // nhầm bản jitpack cache cũ.
        // TỰ ĐỘNG: dùng đúng commit mà tag "pre-release" đang trỏ tới NGAY LÚC build
        // này chạy (xem resolvePreReleaseCommitHash() ở đầu file) — không còn hardcode
        // tay, nên compile-time stub và runtime classes.jar (tải qua overrideUrlPrefix
        // ở trên, cũng theo tag "pre-release") luôn tự khớp nhau.
        //
        // LƯU Ý QUAN TRỌNG: cách này chỉ đúng nếu bạn build LẠI PLUGIN mỗi khi build
        // lại APP (APK mới = tag pre-release đã move sang commit mới). Nếu bạn build
        // app xong, ĐỢI một lúc rồi mới build plugin, và trong lúc đó push thêm commit
        // khác lên fork, tag sẽ move tiếp -> vẫn có thể lệch. An toàn nhất: build app
        // và build plugin ngay sát nhau, không push gì ở giữa.
        cloudstream("com.github.Elv0nne.cloudstream:library:$preReleaseCommitHash")

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
