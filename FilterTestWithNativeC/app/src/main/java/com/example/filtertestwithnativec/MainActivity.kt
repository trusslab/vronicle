package com.example.filtertestwithnativec

import android.content.Intent
import android.net.Uri
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.provider.MediaStore
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import com.anggrayudi.storage.media.MediaFile
import java.io.File

const val REQUEST_VIDEO_CAPTURE = 1
const val TAG = "MainActivity"

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val resultTextView: TextView = findViewById(R.id.filter_test_result_textview)
        val testBlurFilterButton: Button = findViewById(R.id.test_blur_filter_button)
        val testGrayFilterButton: Button = findViewById(R.id.test_gray_filter_button)
        val testDenoiseFilterButton: Button = findViewById(R.id.test_denoise_filter_button)

        val ipAddressEditText: EditText = findViewById(R.id.activity_main_ip_address_edittext)
        val portEditText: EditText = findViewById(R.id.activity_main_port_edittext)
        val recordAndUploadButton: Button = findViewById(R.id.activity_main_record_video_and_upload_button)

        val num_of_rounds_to_run = 60

        testBlurFilterButton.setOnClickListener{
            val startTime: Long = System.currentTimeMillis()
            testFilter(0, num_of_rounds_to_run)
            val endTime: Long = System.currentTimeMillis()
            resultTextView.text = (endTime - startTime).toString()
        }

        testGrayFilterButton.setOnClickListener {
            val startTime: Long = System.currentTimeMillis()
            testFilter(2, num_of_rounds_to_run)
            val endTime: Long = System.currentTimeMillis()
            resultTextView.text = (endTime - startTime).toString()
        }

        testDenoiseFilterButton.setOnClickListener {
            val startTime: Long = System.currentTimeMillis()
            testFilter(1, num_of_rounds_to_run)
            val endTime: Long = System.currentTimeMillis()
            resultTextView.text = (endTime - startTime).toString()
        }

        recordAndUploadButton.setOnClickListener {
            dispatchTakeVideoIntent()
        }

    }

    external fun testFilter(testNum: Int, num_of_rounds: Int): Int

    private fun dispatchTakeVideoIntent() {
        Intent(MediaStore.ACTION_VIDEO_CAPTURE).also { takeVideoIntent ->
            takeVideoIntent.resolveActivity(packageManager)?.also {
                startActivityForResult(takeVideoIntent, REQUEST_VIDEO_CAPTURE)
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, intent: Intent?) {
        super.onActivityResult(requestCode, resultCode, intent)

        if (requestCode == REQUEST_VIDEO_CAPTURE && resultCode == RESULT_OK) {
            val videoUri: Uri = intent?.data!!
            val recordedVideo = MediaFile(applicationContext, videoUri)
            Log.d(TAG, "onActivityResult: the videoUri we get is: ${recordedVideo.absolutePath}, existOrNot: ${recordedVideo.exists}, potentialSize: ${recordedVideo.length}")
            val videoByteArray = File(recordedVideo.absolutePath).readBytes()
            Log.d(TAG, "onActivityResult: ${videoByteArray.size} have been read into RAM...")
        }

    }

    companion object {
        // Used to load the 'native-lib' library on application startup.
        init {
            System.loadLibrary("native-lib")
        }
    }
}