package com.example.filtertestwithnativec

import android.content.Intent
import android.net.Uri
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
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
import java.security.SecureRandom

const val REQUEST_VIDEO_CAPTURE = 1
const val TAG = "MainActivity"
const val SAFETYNET_API_KEY = "AIzaSyBAOSS3cY4thIfO-9rY3aptpLJsOMKI1hM"

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

        read_keys("/sdcard/camera_pri", "/sdcard/camera_pub")

        recordAndUploadButton.setOnClickListener {
//            dispatchTakeVideoIntent()
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
            initializeSafetyNetVerification()
//            Log.d(TAG, "len of direct copy: ${"eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGbERDQ0JIeWdBd0lCQWdJUkFQUWdpNWZxN3EvQkFnQUFBQUNFUGRZd0RRWUpLb1pJaHZjTkFRRUxCUUF3UWpFTE1Ba0dBMVVFQmhNQ1ZWTXhIakFjQmdOVkJBb1RGVWR2YjJkc1pTQlVjblZ6ZENCVFpYSjJhV05sY3pFVE1CRUdBMVVFQXhNS1IxUlRJRU5CSURGUE1UQWVGdzB5TURFeU1UVXhNREUxTlRGYUZ3MHlNVEEyTVRNeE1ERTFOVEJhTUd3eEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxTmIzVnVkR0ZwYmlCV2FXVjNNUk13RVFZRFZRUUtFd3BIYjI5bmJHVWdURXhETVJzd0dRWURWUVFERXhKaGRIUmxjM1F1WVc1a2NtOXBaQzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNwYmx2WFhpejJrRGkrNFBKL1o1ZGRpdG9FckhyTkZwWWJteGdEM3BxQXA1U2xQeEVwUXNPdzRnWTZtWkJpelUxWWJrdXZxZFkwMUd3QVBOUk5MeEgrVHJPbk1TOGQ1U2FGbXcrMWd1V3Q5a0twajVveUN4dmtkSXBWQmp5bmg3amxQcTZCYndFblpOazBvb01hTW5yRW5Ebmpxb2N0Z095T1hFdmFTWlhwaktSaWRKL2k0dFhGWXU2SUtOakQrQkN1VXVNdGNKRjNvRHpFYVpQdlpnNzU4NFpmSnZHaHI3dlYvMy9VVjdlQlNQZXFBSkxNYWtkRFgyMlE1ekxKMnNUaUs2blhxZGhpUlVma1ZycDdRTFFxTVZCVzd4US82ZzZYdXYxZ2VyYTRjbktzS1hxY1dxUllCUWx4Ujltemw4UmVyQ2FGRXJZK2Q0bnV0anJ6TlNYN0FnTUJBQUdqZ2dKWk1JSUNWVEFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd0V3REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVV1RGxJUktOSW5hdkZkYzF0ZkllZCt1WTE4M1F3SHdZRFZSMGpCQmd3Rm9BVW1OSDRiaERyejV2c1lKOFlrQnVnNjMwSi9Tc3daQVlJS3dZQkJRVUhBUUVFV0RCV01DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd09pOHZiMk56Y0M1d2Eya3VaMjl2Wnk5bmRITXhiekV3S3dZSUt3WUJCUVVITUFLR0gyaDBkSEE2THk5d2Eya3VaMjl2Wnk5bmMzSXlMMGRVVXpGUE1TNWpjblF3SFFZRFZSMFJCQll3RklJU1lYUjBaWE4wTG1GdVpISnZhV1F1WTI5dE1DRUdBMVVkSUFRYU1CZ3dDQVlHWjRFTUFRSUNNQXdHQ2lzR0FRUUIxbmtDQlFNd0x3WURWUjBmQkNnd0pqQWtvQ0tnSUlZZWFIUjBjRG92TDJOeWJDNXdhMmt1WjI5dlp5OUhWRk14VHpFdVkzSnNNSUlCQlFZS0t3WUJCQUhXZVFJRUFnU0I5Z1NCOHdEeEFIY0E3c0NWN28xeVpBK1M0OE81RzhjU28ybHFDWHRMYWhvVU9PWkhzc3Z0eGZrQUFBRjJaaDBhc1FBQUJBTUFTREJHQWlFQW9wL05BemFZV1BWWDFDNld2amF3QkY3Mm5xTjRwNjdLVTdhRzBhd0U4K1FDSVFEVFV6VjJndDYwdmhaZElyb2pLZ1VCb25HY1ZOd1hvdFluREY1V01tRXpBd0IyQVBaY2xDL1JkekFpRkZRWUNEQ1VWbzdqVFJNWk03L2ZEQzhnQzh4TzhXVGpBQUFCZG1ZZEdqNEFBQVFEQUVjd1JRSWdDT1l1ZmVKR0xSMzU5UGpYemI4c0NmWVdtaGlQeHZEZk9zWFlHMzN2d2l3Q0lRQ3lOMHRydHlyTFJHbjNVdUY5SG1KRUNHNEVDTmhLU1c0aUw1VG54NXhBRlRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQVgwMnFKV1RsTlowekZXa3NBMjJsY3A1bEVEV0lZdEc4cXp4cWhOVmZsNlFxUzRFcjFkaFFFbnc3eSt4cDhOTVpSWXZRZVRFeVRGL1FBTnZCYUtUUmlXaWZJOTZBZkJKcDJVUFZMcVpUK3Jwc216UGM1TXpwaERBVW1NRlV3U0JEODAxUkVoUjgvTW5CdFg2aXEwcjc2WlVheVN3dVZ5WGNUWmQwK3cwRkdTbWZVZG1lTUY2Uno5QW9kVXFFMWNEa3NudmI0QzNwUnZOcm9mbXBsSUF2WGdnL3RmR1VWRXVuS3lTMjBnczN4WDROMklRZDRxNlUzRk1oaWN2ejI2T2xrK3krM01xOVNSTkdiZk82dmhib2hEc09nYnNMdzY3aDN3ZlFON2lzYmhKcDRIR2hsdm5mKysxL1ZvdmdmYythUGFVUklCdWFSR1NVK2hEWkxrbXV3Zz09IiwiTUlJRVNqQ0NBektnQXdJQkFnSU5BZU8wbXFHTmlxbUJKV2xRdURBTkJna3Foa2lHOXcwQkFRc0ZBREJNTVNBd0hnWURWUVFMRXhkSGJHOWlZV3hUYVdkdUlGSnZiM1FnUTBFZ0xTQlNNakVUTUJFR0ExVUVDaE1LUjJ4dlltRnNVMmxuYmpFVE1CRUdBMVVFQXhNS1IyeHZZbUZzVTJsbmJqQWVGdzB4TnpBMk1UVXdNREF3TkRKYUZ3MHlNVEV5TVRVd01EQXdOREphTUVJeEN6QUpCZ05WQkFZVEFsVlRNUjR3SEFZRFZRUUtFeFZIYjI5bmJHVWdWSEoxYzNRZ1UyVnlkbWxqWlhNeEV6QVJCZ05WQkFNVENrZFVVeUJEUVNBeFR6RXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEUUdNOUYxSXZOMDV6a1FPOSt0TjFwSVJ2Snp6eU9USFc1RHpFWmhEMmVQQ252VUEwUWsyOEZnSUNmS3FDOUVrc0M0VDJmV0JZay9qQ2ZDM1IzVlpNZFMvZE40WktDRVBaUnJBekRzaUtVRHpScm1CQko1d3VkZ3puZElNWWNMZS9SR0dGbDV5T0RJS2dqRXYvU0pIL1VMK2RFYWx0TjExQm1zSytlUW1NRisrQWN4R05ocjU5cU0vOWlsNzFJMmROOEZHZmNkZHd1YWVqNGJYaHAwTGNRQmJqeE1jSTdKUDBhTTNUNEkrRHNheG1LRnNianphVE5DOXV6cEZsZ09JZzdyUjI1eG95blV4djh2Tm1rcTd6ZFBHSFhreFdZN29HOWorSmtSeUJBQms3WHJKZm91Y0JaRXFGSkpTUGs3WEEwTEtXMFkzejVvejJEMGMxdEpLd0hBZ01CQUFHamdnRXpNSUlCTHpBT0JnTlZIUThCQWY4RUJBTUNBWVl3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdIUVlEVlIwT0JCWUVGSmpSK0c0UTY4K2I3R0NmR0pBYm9PdDlDZjByTUI4R0ExVWRJd1FZTUJhQUZKdmlCMWRuSEI3QWFnYmVXYlNhTGQvY0dZWXVNRFVHQ0NzR0FRVUZCd0VCQkNrd0p6QWxCZ2dyQmdFRkJRY3dBWVlaYUhSMGNEb3ZMMjlqYzNBdWNHdHBMbWR2YjJjdlozTnlNakF5QmdOVkhSOEVLekFwTUNlZ0phQWpoaUZvZEhSd09pOHZZM0pzTG5CcmFTNW5iMjluTDJkemNqSXZaM055TWk1amNtd3dQd1lEVlIwZ0JEZ3dOakEwQmdabmdRd0JBZ0l3S2pBb0JnZ3JCZ0VGQlFjQ0FSWWNhSFIwY0hNNkx5OXdhMmt1WjI5dlp5OXlaW".length}")
//            Log.d(TAG, "Let's see: ${parseToJWS("eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGbERDQ0JIeWdBd0lCQWdJUkFQUWdpNWZxN3EvQkFnQUFBQUNFUGRZd0RRWUpLb1pJaHZjTkFRRUxCUUF3UWpFTE1Ba0dBMVVFQmhNQ1ZWTXhIakFjQmdOVkJBb1RGVWR2YjJkc1pTQlVjblZ6ZENCVFpYSjJhV05sY3pFVE1CRUdBMVVFQXhNS1IxUlRJRU5CSURGUE1UQWVGdzB5TURFeU1UVXhNREUxTlRGYUZ3MHlNVEEyTVRNeE1ERTFOVEJhTUd3eEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxTmIzVnVkR0ZwYmlCV2FXVjNNUk13RVFZRFZRUUtFd3BIYjI5bmJHVWdURXhETVJzd0dRWURWUVFERXhKaGRIUmxjM1F1WVc1a2NtOXBaQzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNwYmx2WFhpejJrRGkrNFBKL1o1ZGRpdG9FckhyTkZwWWJteGdEM3BxQXA1U2xQeEVwUXNPdzRnWTZtWkJpelUxWWJrdXZxZFkwMUd3QVBOUk5MeEgrVHJPbk1TOGQ1U2FGbXcrMWd1V3Q5a0twajVveUN4dmtkSXBWQmp5bmg3amxQcTZCYndFblpOazBvb01hTW5yRW5Ebmpxb2N0Z095T1hFdmFTWlhwaktSaWRKL2k0dFhGWXU2SUtOakQrQkN1VXVNdGNKRjNvRHpFYVpQdlpnNzU4NFpmSnZHaHI3dlYvMy9VVjdlQlNQZXFBSkxNYWtkRFgyMlE1ekxKMnNUaUs2blhxZGhpUlVma1ZycDdRTFFxTVZCVzd4US82ZzZYdXYxZ2VyYTRjbktzS1hxY1dxUllCUWx4Ujltemw4UmVyQ2FGRXJZK2Q0bnV0anJ6TlNYN0FnTUJBQUdqZ2dKWk1JSUNWVEFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd0V3REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVV1RGxJUktOSW5hdkZkYzF0ZkllZCt1WTE4M1F3SHdZRFZSMGpCQmd3Rm9BVW1OSDRiaERyejV2c1lKOFlrQnVnNjMwSi9Tc3daQVlJS3dZQkJRVUhBUUVFV0RCV01DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd09pOHZiMk56Y0M1d2Eya3VaMjl2Wnk5bmRITXhiekV3S3dZSUt3WUJCUVVITUFLR0gyaDBkSEE2THk5d2Eya3VaMjl2Wnk5bmMzSXlMMGRVVXpGUE1TNWpjblF3SFFZRFZSMFJCQll3RklJU1lYUjBaWE4wTG1GdVpISnZhV1F1WTI5dE1DRUdBMVVkSUFRYU1CZ3dDQVlHWjRFTUFRSUNNQXdHQ2lzR0FRUUIxbmtDQlFNd0x3WURWUjBmQkNnd0pqQWtvQ0tnSUlZZWFIUjBjRG92TDJOeWJDNXdhMmt1WjI5dlp5OUhWRk14VHpFdVkzSnNNSUlCQlFZS0t3WUJCQUhXZVFJRUFnU0I5Z1NCOHdEeEFIY0E3c0NWN28xeVpBK1M0OE81RzhjU28ybHFDWHRMYWhvVU9PWkhzc3Z0eGZrQUFBRjJaaDBhc1FBQUJBTUFTREJHQWlFQW9wL05BemFZV1BWWDFDNld2amF3QkY3Mm5xTjRwNjdLVTdhRzBhd0U4K1FDSVFEVFV6VjJndDYwdmhaZElyb2pLZ1VCb25HY1ZOd1hvdFluREY1V01tRXpBd0IyQVBaY2xDL1JkekFpRkZRWUNEQ1VWbzdqVFJNWk03L2ZEQzhnQzh4TzhXVGpBQUFCZG1ZZEdqNEFBQVFEQUVjd1JRSWdDT1l1ZmVKR0xSMzU5UGpYemI4c0NmWVdtaGlQeHZEZk9zWFlHMzN2d2l3Q0lRQ3lOMHRydHlyTFJHbjNVdUY5SG1KRUNHNEVDTmhLU1c0aUw1VG54NXhBRlRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQVgwMnFKV1RsTlowekZXa3NBMjJsY3A1bEVEV0lZdEc4cXp4cWhOVmZsNlFxUzRFcjFkaFFFbnc3eSt4cDhOTVpSWXZRZVRFeVRGL1FBTnZCYUtUUmlXaWZJOTZBZkJKcDJVUFZMcVpUK3Jwc216UGM1TXpwaERBVW1NRlV3U0JEODAxUkVoUjgvTW5CdFg2aXEwcjc2WlVheVN3dVZ5WGNUWmQwK3cwRkdTbWZVZG1lTUY2Uno5QW9kVXFFMWNEa3NudmI0QzNwUnZOcm9mbXBsSUF2WGdnL3RmR1VWRXVuS3lTMjBnczN4WDROMklRZDRxNlUzRk1oaWN2ejI2T2xrK3krM01xOVNSTkdiZk82dmhib2hEc09nYnNMdzY3aDN3ZlFON2lzYmhKcDRIR2hsdm5mKysxL1ZvdmdmYythUGFVUklCdWFSR1NVK2hEWkxrbXV3Zz09IiwiTUlJRVNqQ0NBektnQXdJQkFnSU5BZU8wbXFHTmlxbUJKV2xRdURBTkJna3Foa2lHOXcwQkFRc0ZBREJNTVNBd0hnWURWUVFMRXhkSGJHOWlZV3hUYVdkdUlGSnZiM1FnUTBFZ0xTQlNNakVUTUJFR0ExVUVDaE1LUjJ4dlltRnNVMmxuYmpFVE1CRUdBMVVFQXhNS1IyeHZZbUZzVTJsbmJqQWVGdzB4TnpBMk1UVXdNREF3TkRKYUZ3MHlNVEV5TVRVd01EQXdOREphTUVJeEN6QUpCZ05WQkFZVEFsVlRNUjR3SEFZRFZRUUtFeFZIYjI5bmJHVWdWSEoxYzNRZ1UyVnlkbWxqWlhNeEV6QVJCZ05WQkFNVENrZFVVeUJEUVNBeFR6RXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEUUdNOUYxSXZOMDV6a1FPOSt0TjFwSVJ2Snp6eU9USFc1RHpFWmhEMmVQQ252VUEwUWsyOEZnSUNmS3FDOUVrc0M0VDJmV0JZay9qQ2ZDM1IzVlpNZFMvZE40WktDRVBaUnJBekRzaUtVRHpScm1CQko1d3VkZ3puZElNWWNMZS9SR0dGbDV5T0RJS2dqRXYvU0pIL1VMK2RFYWx0TjExQm1zSytlUW1NRisrQWN4R05ocjU5cU0vOWlsNzFJMmROOEZHZmNkZHd1YWVqNGJYaHAwTGNRQmJqeE1jSTdKUDBhTTNUNEkrRHNheG1LRnNianphVE5DOXV6cEZsZ09JZzdyUjI1eG95blV4djh2Tm1rcTd6ZFBHSFhreFdZN29HOWorSmtSeUJBQms3WHJKZm91Y0JaRXFGSkpTUGs3WEEwTEtXMFkzejVvejJEMGMxdEpLd0hBZ01CQUFHamdnRXpNSUlCTHpBT0JnTlZIUThCQWY4RUJBTUNBWVl3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdIUVlEVlIwT0JCWUVGSmpSK0c0UTY4K2I3R0NmR0pBYm9PdDlDZjByTUI4R0ExVWRJd1FZTUJhQUZKdmlCMWRuSEI3QWFnYmVXYlNhTGQvY0dZWXVNRFVHQ0NzR0FRVUZCd0VCQkNrd0p6QWxCZ2dyQmdFRkJRY3dBWVlaYUhSMGNEb3ZMMjlqYzNBdWNHdHBMbWR2YjJjdlozTnlNakF5QmdOVkhSOEVLekFwTUNlZ0phQWpoaUZvZEhSd09pOHZZM0pzTG5CcmFTNW5iMjluTDJkemNqSXZaM055TWk1amNtd3dQd1lEVlIwZ0JEZ3dOakEwQmdabmdRd0JBZ0l3S2pBb0JnZ3JCZ0VGQlFjQ0FSWWNhSFIwY0hNNkx5OXdhMmt1WjI5dlp5OXlaWEJ2YzJsMGIzSjVMekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBR29BK05ubjc4eTZwUmpkOVhsUVdOYTdIVGdpWi9yM1JOR2ttVW1ZSFBRcTZTY3RpOVBFYWp2d1JUMmlXVEhRcjAyZmVzcU9xQlkyRVRVd2daUStsbHRvTkZ2aHNPOXR2QkNPSWF6cHN3V0M5YUo5eGp1NHRXRFFIOE5WVTZZWlovWHRlRFNHVTlZekpxUGpZOHEzTUR4cnptcWVwQkNmNW84bXcvd0o0YTJHNnh6VXI2RmI2VDhNY0RPMjJQTFJMNnUzTTRUenMzQTJNMWo2YnlrSllpOHdXSVJkQXZLTFdadS9heEJWYnpZbXFtd2ttNXpMU0RXNW5JQUpiRUxDUUNad01INTZ0MkR2cW9meHM2QkJjQ0ZJWlVTcHh1Nng2dGQwVjdTdkpDQ29zaXJTbUlhdGovOWRTU1ZEUWliZXQ4cS83VUs0djRaVU44MGF0blp6MXlnPT0iXX0.eyJub25jZSI6ImFyTjMxOWlsd0pzM2MyaW1TNHNQWGc9PSIsInRpbWVzdGFtcE1zIjoxNjE3NjU3MjEyNjY5LCJhcGtQYWNrYWdlTmFtZSI6ImNvbS5leGFtcGxlLmZpbHRlcnRlc3R3aXRobmF0aXZlYyIsImFwa0RpZ2VzdFNoYTI1NiI6IllMQ3c3UEl4MlpLT3h4NTlwVzZEdUhwZkVsYy9RWmdBVGpUK0s1SUI5cVE9IiwiY3RzUHJvZmlsZU1hdGNoIjp0cnVlLCJhcGtDZXJ0aWZpY2F0ZURpZ2VzdFNoYTI1NiI6WyJseG9rSHkvSUJnUlliNklGTTlnWFR5SklzSzdKdHNPb0ZvWGk0YnNKMzZzPSJdLCJiYXNpY0ludGVncml0eSI6dHJ1ZSwiZXZhbHVhdGlvblR5cGUiOiJCQVNJQyJ9.FxtiP-G0HrTo-6pQfp6hxx73BKxs33VrMDBOBuNloIJsH5V1sOF-2de8Dv9IxOQ0QL4yfLElNeGGPV1qWQ5vaC5nLmG5W78b3SjB2jwstHrop-PuU8V3PiiCmoPjAkIF2p8k2KgSaIsTVvKB6JVu1NSEx6keey2mGuiFmxoRiq0ttfPP5rIhkokGTk01bWlr0xAmVFho5yvQ78y03C8eOz3ny1pjOHHkEJX7IvccgsQPx_gj-_TmOH3HjgP2G66FZ2u4R_LOEYSIIhFcv8LbnmOvnlixUN5-vt1L5ezd7m61InHo_xj4UtDEkxWK8_2bt_KWbPn2kmfqIKU0m5peoA")}")
        }


    }

    external fun testFilter(testNum: Int, num_of_rounds: Int): Int
    external fun establish_connection(ipAddress: String, port: Int): Int
    external fun generate_metadata(gWidth: Int, gHeight: Int, fps: Int, numOfFrames: Int): String
    external fun read_keys(camPriKeyStr: String, camPubKeyStr: String): Int

    private fun dispatchTakeVideoIntent() {
        Intent(MediaStore.ACTION_VIDEO_CAPTURE).also { takeVideoIntent ->
            takeVideoIntent.resolveActivity(packageManager)?.also {
                startActivityForResult(takeVideoIntent, REQUEST_VIDEO_CAPTURE)
            }
        }
    }

    private fun initializeSafetyNetVerification() {
        if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(baseContext)
                != ConnectionResult.SUCCESS) {
            Toast.makeText(baseContext, getString(R.string.google_play_services_not_available), Toast.LENGTH_LONG).show();
            return;
        }

        val secureRandom = SecureRandom()
        val n = ByteArray(16)
        secureRandom.nextBytes(n)
        Thread {
            requestAttestation(n)
        }.start()

        Toast.makeText(baseContext, getString(R.string.safetynet_quote_requested), Toast.LENGTH_LONG).show();
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

    private fun requestAttestation(nonce: ByteArray) {
        SafetyNet.getClient(this).attest(nonce, SAFETYNET_API_KEY)
                .addOnSuccessListener( OnSuccessListener {
                    val token = it.jwsResult
                    Log.d(TAG, "len of new token: ${token.length}")
                    Log.d(TAG, "Got token back: ${token.subSequence(0, 2000)}")
                    Log.d(TAG, "Got token back(2): ${token.subSequence(2000, 4000)}")
                    Log.d(TAG, "Got token back(3): ${token.subSequence(4000, token.length)}")
                    val data = parseToJWS(token)
                    Log.d(TAG, "After parsing to jws: $data")
                })
                .addOnFailureListener(this) { e ->
                    if (e is ApiException) {
                        val apiException = e as ApiException
                        Log.d(TAG, "error with Safetynet Quote Request: ${apiException.statusCode} : ${apiException.status.statusMessage}")
                    } else {
                        Log.d(TAG, "unknown error with Safetynet Quote Request: ${e.message}")
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
            System.loadLibrary("tcp-client")
        }
    }
}