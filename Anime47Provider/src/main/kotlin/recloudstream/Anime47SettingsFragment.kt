package recloudstream

import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.DialogFragment
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import androidx.preference.PreferenceFragmentCompat

class Anime47SettingsFragment : PreferenceFragmentCompat() {

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        val context = preferenceManager.context
        val screen = preferenceManager.createPreferenceScreen(context)

        preferenceManager.sharedPreferencesName = "anime47_prefs"
        val prefs = preferenceManager.sharedPreferences

        val accountCategory = PreferenceCategory(context).apply {
            title = "Tài khoản Anime47"
        }
        screen.addPreference(accountCategory)

        val emailPref = EditTextPreference(context).apply {
            key = "anime47_email"
            title = "Email"
            val savedEmail = prefs?.getString("anime47_email", "") ?: ""
            summary = if (savedEmail.isBlank()) "Chưa thiết lập" else savedEmail
            setOnPreferenceChangeListener { pref, newValue ->
                val text = newValue.toString()
                pref.summary = if (text.isBlank()) "Chưa thiết lập" else text
                true
            }
        }

        val passwordPref = EditTextPreference(context).apply {
            key = "anime47_password"
            title = "Mật khẩu"
            val savedPassword = prefs?.getString("anime47_password", "") ?: ""
            summary = if (savedPassword.isBlank()) "Chưa thiết lập" else "********"
            setOnBindEditTextListener { editText ->
                editText.inputType =
                    android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            setOnPreferenceChangeListener { pref, newValue ->
                val text = newValue.toString()
                pref.summary = if (text.isBlank()) "Chưa thiết lập" else "********"
                true
            }
        }

        accountCategory.addPreference(emailPref)
        accountCategory.addPreference(passwordPref)

        val optionsCategory = PreferenceCategory(context).apply {
            title = "Tùy chọn"
        }
        screen.addPreference(optionsCategory)

        val clearCredentialsPref = Preference(context).apply {
            title = "Xóa thông tin đăng nhập"
            summary = "Xóa tài khoản khỏi thiết bị"
            setIcon(android.R.drawable.ic_menu_delete)
            setOnPreferenceClickListener {
                prefs?.edit()?.apply {
                    remove("anime47_email")
                    remove("anime47_password")
                    apply()
                }
                // SỬA LỖI: trước đây chỉ xoá SharedPreferences, còn token đã đăng nhập
                // vẫn nằm trong bộ nhớ của Anime47Provider đang chạy nên tài khoản coi
                // như chưa thực sự đăng xuất khỏi phiên hiện tại (vẫn tiếp tục gọi API
                // bằng token cũ cho tới khi nó tự hết hạn). Gọi thẳng vào companion của
                // provider để vô hiệu hoá token đang cache ngay lập tức.
                Anime47Provider.invalidateCachedSession()
                emailPref.summary = "Chưa thiết lập"
                emailPref.text = ""
                passwordPref.summary = "Chưa thiết lập"
                passwordPref.text = ""
                Toast.makeText(context, "Đã xóa tài khoản", Toast.LENGTH_SHORT).show()
                true
            }
        }

        val closePref = Preference(context).apply {
            title = "Xong / Đóng"
            summary = "Lưu thiết lập và thoát"
            setIcon(android.R.drawable.ic_menu_save)
            setOnPreferenceClickListener {
                val dialog = parentFragment as? DialogFragment
                dialog?.dismiss()
                true
            }
        }

        optionsCategory.addPreference(clearCredentialsPref)
        optionsCategory.addPreference(closePref)

        preferenceScreen = screen
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        view.layoutParams = view.layoutParams?.apply {
            width = ViewGroup.LayoutParams.MATCH_PARENT
            height = ViewGroup.LayoutParams.WRAP_CONTENT
        }

        listView.layoutParams = listView.layoutParams?.apply {
            width = ViewGroup.LayoutParams.MATCH_PARENT
            height = ViewGroup.LayoutParams.WRAP_CONTENT
        }

        listView.isNestedScrollingEnabled = false
        listView.overScrollMode = View.OVER_SCROLL_NEVER
    }
}
