package recloudstream

import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import androidx.fragment.app.DialogFragment
import kotlin.math.min

class Anime47SettingsDialog : DialogFragment() {

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val containerId = View.generateViewId()

        val frameLayout = FrameLayout(requireContext()).apply {
            id = containerId
            val paddingPx = (8 * resources.displayMetrics.density).toInt()
            setPadding(paddingPx, paddingPx, paddingPx, paddingPx)
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        childFragmentManager.beginTransaction()
            .replace(containerId, Anime47SettingsFragment())
            .commit()

        return frameLayout
    }

    override fun onStart() {
        super.onStart()
        val window = dialog?.window ?: return

        val metrics = resources.displayMetrics
        val desiredWidth = (340 * metrics.density).toInt()
        val maxWidth = (metrics.widthPixels * 0.85).toInt()
        val width = min(desiredWidth, maxWidth)

        window.setLayout(width, ViewGroup.LayoutParams.WRAP_CONTENT)
        window.setGravity(android.view.Gravity.CENTER)
        window.setBackgroundDrawableResource(android.R.color.transparent)
    }
}
