package com.example.filtertestwithnativec

import android.content.Intent
import android.media.MediaMetadataRetriever
import android.net.Uri
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.provider.MediaStore
import android.text.method.ScrollingMovementMethod
import android.util.Log
import android.widget.*
import androidx.appcompat.app.AlertDialog
import com.anggrayudi.storage.media.MediaFile
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.safetynet.SafetyNet
import com.google.android.gms.tasks.OnSuccessListener
import com.google.api.client.json.jackson2.JacksonFactory
import com.google.api.client.json.webtoken.JsonWebSignature
import java.io.File
import java.io.IOException
import java.lang.StringBuilder
import java.util.*
import kotlin.collections.ArrayList

const val REQUEST_VIDEO_CAPTURE = 1
const val PICK_VIDEO_FILE = 2
const val TAG = "MainActivity"
const val SAFETYNET_API_KEY = "AIzaSyBAOSS3cY4thIfO-9rY3aptpLJsOMKI1hM"

class MainActivity : AppCompatActivity() {

    private lateinit var recordedVideo: MediaFile
    private lateinit var videoByteArray: ByteArray
    private lateinit var chosenFileTextView: TextView
    private lateinit var statusTextView: TextView
    private lateinit var ipAddressEditText: EditText
    private lateinit var portEditText: EditText
    private lateinit var chosenFiltersTextView: TextView

    private lateinit var pubkeyB64: String
    private lateinit var hashOfPubKey: String
    private lateinit var firstAttestationReport: String
    private lateinit var secondAttestationReport: String
    private var chosenFiltersNames:ArrayList<String> = ArrayList<String>()
    private var chosenFiltersParameterNums:ArrayList<Int> = ArrayList<Int>()
    private var chosenFiltersParameters:ArrayList<Double> = ArrayList<Double>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val resultTextView: TextView = findViewById(R.id.filter_test_result_textview)
        val testBlurFilterButton: Button = findViewById(R.id.test_blur_filter_button)
        val testGrayFilterButton: Button = findViewById(R.id.test_gray_filter_button)
        val testDenoiseFilterButton: Button = findViewById(R.id.test_denoise_filter_button)

        ipAddressEditText = findViewById(R.id.activity_main_ip_address_edittext)
        portEditText = findViewById(R.id.activity_main_port_edittext)
        val recordButton: Button = findViewById(R.id.activity_main_record_video_button)
        chosenFileTextView = findViewById(R.id.activity_main_chosen_file_textview)
        chosenFiltersTextView = findViewById(R.id.activity_main_chosen_filters_textview)
        val addFilterButton: Button = findViewById(R.id.activity_main_add_filter_button)
        val uploadButton: Button = findViewById(R.id.activity_main_upload_button)
        statusTextView = findViewById(R.id.activity_main_status_textview)

        chosenFiltersTextView.movementMethod = ScrollingMovementMethod()
        statusTextView.movementMethod = ScrollingMovementMethod()

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

//        val resultOfReadingKeys = read_keys("/sdcard/vronicle/camera_pri", "/sdcard/vronicle/camera_pub")
//        if (resultOfReadingKeys != 0) {
//            Toast.makeText(baseContext, "Keys cannot be read from sdcard/vronicle folder...", Toast.LENGTH_SHORT).show()
//        }

        if (generate_keypair() != 0) {
            updateStatusTextViewWithInfo("[Error] Key pair cannot be generated", true)
        } else {
            updateStatusTextViewWithInfo("[Success] Key pair generated", true)
            hashOfPubKey = get_hash_of_pubkey()
            Log.d(TAG, "onCreate: hashOfPubKey: $hashOfPubKey")
            if (hashOfPubKey.isEmpty()) {
                updateStatusTextViewWithInfo("[Error] Hash of pubkey cannot be generated", true);
            } else if (hashOfPubKey == get_hash_of_pubkey()) {
                updateStatusTextViewWithInfo("[Success] Hash of pubkey integrity is checked", true);
            } else {
                updateStatusTextViewWithInfo("[Error] Hash of pubkey integrity check is failed", true);
            }

            pubkeyB64 = get_pubkey()
//            Log.d(TAG, "The pubkey we get is: {$pubkeyB64}")

//            print_hash_of_pubkey(pubkeyB64)

            doFirstSafetyNetAttestation(hashOfPubKey)

        }

        recordButton.setOnClickListener {
            dispatchTakeVideoIntent()
//            Thread(Runnable {
//                Log.d(TAG, "onCreate: going to try connect to ip: " + ipAddressEditText.text.toString() + " with port: " + portEditText.text.toString().toInt())
//                val resultOfConnection = establish_connection(ipAddressEditText.text.toString(), portEditText.text.toString().toInt())
//                Log.d(TAG, "onCreate: the connection result is: $resultOfConnection")
//            }).start()
//            val metadataCharArray: CharArray = generate_metadata(1280, 720, 30, 60)
//            val metadataString: String = generate_metadata(1280, 720, 30, 60)
//            Log.d(TAG, "onCreate: the metadata we get is: {$metadataString}")
//            val resultOfConnection = establish_connection(ipAddressEditText.text.toString(), portEditText.text.toString().toInt())
//            Log.d(TAG, "onCreate: the connection result is: $resultOfConnection")
//            initializeSafetyNetVerification()
        }

        chosenFileTextView.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            startActivityForResult(intent, PICK_VIDEO_FILE)
        }


        uploadButton.setOnClickListener {

            if (hashOfPubKey.isEmpty() || firstAttestationReport.isEmpty()) {
                Toast.makeText(baseContext, "First SafetyNet Attestation is still not completed", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            doSecondSafetyNetAttestationAndAttemptUpload(hashOfPubKey);
            
        }

        addFilterButton.setOnClickListener {
            val builder: AlertDialog.Builder = AlertDialog.Builder(this)
            builder.setTitle("Add a new filter")
            val dialogLayout = layoutInflater.inflate(R.layout.add_filter, null)
            val filtersRadioGroup = dialogLayout.findViewById<RadioGroup>(R.id.add_fitler_radioGroup)
            val filterParameterEditText = dialogLayout.findViewById<EditText>(R.id.add_filter_filter_parameter)
            builder.setView(dialogLayout)
            builder.setPositiveButton(android.R.string.yes) { _, _ ->
                var isValidFilterDetected = true
                when (filtersRadioGroup.checkedRadioButtonId) {
                    R.id.add_filter_blur_radioButton -> {
                        chosenFiltersNames.add("blur")
                        chosenFiltersParameterNums.add(1)
                        chosenFiltersParameters.add(filterParameterEditText.text.toString().toDouble())
                    }
                    R.id.add_filter_brightness_radioButton -> {
                        chosenFiltersNames.add("brightness")
                        chosenFiltersParameterNums.add(1)
                        chosenFiltersParameters.add(filterParameterEditText.text.toString().toDouble())
                    }
                    R.id.add_filter_denoise_radioButton -> {
                        chosenFiltersNames.add("denoise_easy")
                        chosenFiltersParameterNums.add(0)
                    }
                    R.id.add_filter_gray_radioButton -> {
                        chosenFiltersNames.add("gray")
                        chosenFiltersParameterNums.add(0)
                    }
                    R.id.add_filter_sharpen_radioButton -> {
                        chosenFiltersNames.add("sharpen")
                        chosenFiltersParameterNums.add(1)
                        chosenFiltersParameters.add(filterParameterEditText.text.toString().toDouble())
                    }
                    R.id.add_filter_white_balance_radioButton -> {
                        chosenFiltersNames.add("white_balance")
                        chosenFiltersParameterNums.add(0)
                    }
                    else -> {
                        isValidFilterDetected = false
                        Toast.makeText(this, "Illegal filter is chosen", Toast.LENGTH_SHORT).show()
                    }
                }
                if (isValidFilterDetected) {
//                    Log.d(TAG, "Trying to print chosenFiltersNames(size: ${chosenFiltersNames.size}): $chosenFiltersNames")
                    updateFiltersInfoTextViewWithInfo(chosenFiltersNames[chosenFiltersNames.size - 1])
                }
            }
            builder.show()
        }

    }

    private fun attemptUploadVideo(): Int {
        // Return 0 on success, otherwise fail
        val videoFileMetadataRetriever = MediaMetadataRetriever()

        // Check if video still exists (note that sometime GC could clean the video in RAM)
        if (recordedVideo.exists) {
            videoFileMetadataRetriever.setDataSource(recordedVideo.absolutePath)
            Log.d(TAG, "onCreate: Metadata: possible framerate: ${videoFileMetadataRetriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_CAPTURE_FRAMERATE)}, possible num_of_frames: ${videoFileMetadataRetriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_FRAME_COUNT)}, " +
                    "possible width: ${videoFileMetadataRetriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH)}, possible height: ${videoFileMetadataRetriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT)}")
        } else {
            runOnUiThread {
                Toast.makeText(baseContext, "Please record or select a file first", Toast.LENGTH_SHORT).show()
            }
            return 1;
        }

        // If no filter is chosen, abort
        if (chosenFiltersNames.isEmpty()) {
            runOnUiThread {
                Toast.makeText(baseContext, "Please add a valid filter first", Toast.LENGTH_SHORT).show()
            }
            return 1;
        }

//            val metadataString: String = generate_metadata(1280, 720, 10, 60)
        val inputOfchosenFiltersParameterNums = IntArray(chosenFiltersParameterNums.size)
        val inputOfchosenFiltersParameters = DoubleArray(chosenFiltersParameters.size)
        for (filterParameterNumsIndex in chosenFiltersParameterNums.indices) {
            inputOfchosenFiltersParameterNums[filterParameterNumsIndex] = chosenFiltersParameterNums[filterParameterNumsIndex]
        }
        for (filterParameterIndex in chosenFiltersParameters.indices) {
            inputOfchosenFiltersParameters[filterParameterIndex] = chosenFiltersParameters[filterParameterIndex]
        }
        Log.d(TAG, "onCreate: chosenFiltersNames.toTypedArray(): ${chosenFiltersNames.toTypedArray()}")
        val metadataString: String = generate_metadata(
                videoFileMetadataRetriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH).toInt(),
                videoFileMetadataRetriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT).toInt(),
                30,
                videoFileMetadataRetriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_FRAME_COUNT).toInt() - 1,  // -1 to delete the last incomplete frame
                firstAttestationReport, secondAttestationReport,
                chosenFiltersNames.toTypedArray(), inputOfchosenFiltersParameterNums, inputOfchosenFiltersParameters
        )
        Log.d(TAG, "onCreate: the metadata we get has length: ${metadataString.length}")
        runOnUiThread {
            updateStatusTextViewWithInfo("[Success] Metadata is generated successfully with size: ${metadataString.length}", true);
        }
        val signatureB64String: String = sign_video_and_metadata(videoByteArray, metadataString)
//            Log.d(TAG, "onCreate: the signature we get is: {$signatureB64String}")
        runOnUiThread {
            updateStatusTextViewWithInfo("[Success] Signature is generated successfully with size: ${signatureB64String.length}", true);
        }
//        val certBtteArray = File("/sdcard/vronicle/camera_cert").readBytes()
////            Log.d(TAG, "onCreate: successfully read certificate from storage: {${String(certBtteArray)}}")
//
        val resultOfConnection = establish_connection(ipAddressEditText.text.toString(), portEditText.text.toString().toInt())
        Log.d(TAG, "onCreate: the connection result is: $resultOfConnection")

        if (resultOfConnection == 1) {
            send_file("meta", metadataString.encodeToByteArray())
            send_file("cert", pubkeyB64.encodeToByteArray())
            send_file("vid", videoByteArray)
            send_file("sig", signatureB64String.encodeToByteArray())

            runOnUiThread {
                updateStatusTextViewWithInfo("[Success] Uploaded successfully!", true);
            }
            close_connection()
        } else {
            return 1;
        }

        return 0;
    }

    private fun updateFiltersInfoTextViewWithInfo(newFilterName: String) {
        chosenFiltersTextView.text = StringBuilder().append(chosenFiltersTextView.text).append("\n").append(newFilterName).toString()
    }

    private fun updateStatusTextViewWithInfo(newInfo: String, enable_newline: Boolean) {
        if (enable_newline) {
            statusTextView.text = StringBuilder().append(statusTextView.text).append("\n").append(newInfo).toString()
        } else {
            statusTextView.text = StringBuilder().append(statusTextView.text).append(newInfo).toString()
        }
    }

    private fun updateChosenFileTextViewWithLatestInfo() {
        chosenFileTextView.text = recordedVideo.absolutePath
    }

    // native-lib
    external fun testFilter(testNum: Int, num_of_rounds: Int): Int
    external fun generate_metadata(
        gWidth: Int, gHeight: Int, fps: Int, numOfFrames: Int,
        firstAttestationReport: String, secondAttestationReport: String,
        filterNames: Array<String>, filterParameterNums: IntArray, filterParameters: DoubleArray
    ): String
    external fun read_keys(camPriKeyStr: String, camPubKeyStr: String): Int
    external fun generate_keypair(): Int
    external fun sign_video_and_metadata(video: ByteArray, metadata: String): String
    external fun get_pubkey(): String    // Not working properly
    external fun print_hash_of_pubkey(pubkey: String): Int    // Not working properly
    external fun get_hash_of_pubkey(): String

    // client
    external fun establish_connection(ipAddress: String, port: Int): Int
    external fun close_connection(): Int
    external fun send_file(file_name: String, file_data: ByteArray): Int

    private fun dispatchTakeVideoIntent() {
        Intent(MediaStore.ACTION_VIDEO_CAPTURE).also { takeVideoIntent ->
            takeVideoIntent.resolveActivity(packageManager)?.also {
                startActivityForResult(takeVideoIntent, REQUEST_VIDEO_CAPTURE)
            }
        }
    }

    private fun doFirstSafetyNetAttestation(nonce: String) {
        if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(baseContext)
                != ConnectionResult.SUCCESS) {
            Toast.makeText(baseContext, getString(R.string.google_play_services_not_available), Toast.LENGTH_LONG).show();
            return;
        }

//        val secureRandom = SecureRandom()
//        val n = ByteArray(16)
//        secureRandom.nextBytes(n)
        Thread {
//            Log.d(TAG, "doFirstSafetyNetAttestation: nonce after encoding(1): ${String(nonce.toByteArray())}")
//            Log.d(TAG, "doFirstSafetyNetAttestation: nonce after encoding(2): ${String(nonce.toByteArray(), StandardCharsets.US_ASCII)}")
//            Log.d(TAG, "doFirstSafetyNetAttestation: nonce after encoding(2): ${String(nonce.toByteArray(), StandardCharsets.UTF_8)}")
            requestAttestation(nonce.toByteArray(), 0)
//            requestAttestation("aaaaaaaaaaaaaaaa".toByteArray(), 0)
        }.start()

//        Toast.makeText(baseContext, getString(R.string.safetynet_quote_requested), Toast.LENGTH_LONG).show();
        updateStatusTextViewWithInfo("[Info] First SafetyNet Attestation request is sent", true);
    }

    private fun doSecondSafetyNetAttestationAndAttemptUpload(nonce: String) {
        if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(baseContext)
                != ConnectionResult.SUCCESS) {
            Toast.makeText(baseContext, getString(R.string.google_play_services_not_available), Toast.LENGTH_LONG).show();
            return;
        }

        Thread {
            secondAttestationReport = ""
            requestAttestation(nonce.toByteArray(), 1)
            while (secondAttestationReport.isEmpty()) {Thread.sleep(1000)}
            attemptUploadVideo()
        }.start()

        updateStatusTextViewWithInfo("[Info] Second SafetyNet Attestation request is sent", true);
    }

    private fun parseToJWS(jwsResult:String): JsonWebSignature {
        var jws: JsonWebSignature? = null
        try {
            jws = JsonWebSignature.parser(JacksonFactory.getDefaultInstance())
                    .parse(jwsResult)
            return jws!!
        } catch (e: IOException) {
            Log.i(TAG, "Failure: "  + " is not valid JWS ")
            return jws!!
        }
    }

    private fun requestAttestation(nonce: ByteArray, outputPosition: Int) {
        // outputPosition: 0 for first, 1 for second

        SafetyNet.getClient(this).attest(nonce, SAFETYNET_API_KEY)
                .addOnSuccessListener( OnSuccessListener {
                    val token:String = it.jwsResult
                    Log.d(TAG, "len of new token: ${token.length}")

//                    Log.d(TAG, "Got token back: ${token.subSequence(0, 2000)}")
//                    Log.d(TAG, "Got token back(2): ${token.subSequence(2000, 4000)}")
//                    Log.d(TAG, "Got token back(3): ${token.subSequence(4000, token.length)}")
                    val data = parseToJWS(token)
                    Log.d(TAG, "After parsing to jws: $data")
                    runOnUiThread {
                        if (outputPosition == 0) {
                            firstAttestationReport = token
                            updateStatusTextViewWithInfo("[Success] First SafetyNet Attestation is done($outputPosition)", true);
                        } else if (outputPosition == 1) {
                            secondAttestationReport = token
                            updateStatusTextViewWithInfo("[Success] Second SafetyNet Attestation is done($outputPosition)", true);
                        } else {
                            updateStatusTextViewWithInfo("[Error] Unknown outputPosition: $outputPosition", true);
                        }
                    }
                })
                .addOnFailureListener(this) { e ->
                    if (e is ApiException) {
                        val apiException = e as ApiException
                        Log.d(TAG, "error with Safetynet Quote Request: ${apiException.statusCode} : ${apiException.status.statusMessage}")
                    } else {
                        Log.d(TAG, "unknown error with Safetynet Quote Request: ${e.message}")
                    }
                    runOnUiThread {
                        updateStatusTextViewWithInfo("[Error] Failure to do SafetyNet Attestation on outputPosition: $outputPosition", true);
                    }
                }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, intent: Intent?) {
        super.onActivityResult(requestCode, resultCode, intent)

        if ( (requestCode == REQUEST_VIDEO_CAPTURE || requestCode == PICK_VIDEO_FILE) && resultCode == RESULT_OK) {
            val videoUri: Uri = intent?.data!!
            recordedVideo = MediaFile(applicationContext, videoUri)
            Log.d(TAG, "onActivityResult: the videoUri we get is: ${videoUri}, the absolutePath we get is: ${recordedVideo.absolutePath}, existOrNot: ${recordedVideo.exists}, potentialSize: ${recordedVideo.length}")
            videoByteArray = File(recordedVideo.absolutePath).readBytes()
            Log.d(TAG, "onActivityResult: ${videoByteArray.size} have been read into RAM...")
            updateChosenFileTextViewWithLatestInfo()
        }

    }

    companion object {
        // Used to load the 'native-lib' library on application startup.
        init {
            System.loadLibrary("native-lib")
            System.loadLibrary("tcp-client")
        }
    }
}