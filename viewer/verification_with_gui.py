#!/usr/bin/env python3
from tkinter import *
import tkinter.scrolledtext as st
from time import *
import sys, os, subprocess
import json

pathToSgxVerification = "./"
pathFromSgxVerification = "./"
pathToSafetynetVerification = "./safetynet_verification/"
pathFromSafetynetVerification = "../"

cmd4SgxVerification = "./sig_verify"
cmd4SafetynetVerification = "./runOnlineVerify"

def update_with_sgx_verification(rootUi, statusLabelToBeUpdated):
    print("SGX verification start time:", round(time() * 1000000))
    process = subprocess.Popen(
        "cd " + pathToSgxVerification + "&&" + cmd4SgxVerification + 
        " " + pathFromSgxVerification + sys.argv[1] + 
        " " + pathFromSgxVerification + sys.argv[2] + 
        " " + pathFromSgxVerification + sys.argv[3] + 
        " " + pathFromSgxVerification + sys.argv[4],
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, shell=True)
    dotCounter = 1
    while process.poll() is None:
        statusLabelToBeUpdated.config(text="Verifying" + "." * dotCounter, fg="yellow")
        dotCounter = (dotCounter + 1) % 4
        rootUi.update()
        sleep(0.3)
    stdout, stderr = process.communicate()

    # Update UI here
    if b"^^SGX Verified^^" in stdout:
        statusLabelToBeUpdated.config(text="Verified!", fg="green")
    else:
        statusLabelToBeUpdated.config(text="Unverified!", fg="red")

    rootUi.update()
    print("SGX verification end time:", round(time() * 1000000))

def seperate_safetynet_verification_result_str(verificationResultStr):
    verificationResultStrLines = verificationResultStr.split("\n")
    verificationResultDicts = []
    tempResultDict = {"is_signature_verified": False}
    isCurrentlyReadingReport = False
    for line in verificationResultStrLines:
        if "^^EndOfSaftyNetOnlineVerify" in line:
            verificationResultDicts.append(tempResultDict)
            isCurrentlyReadingReport = False
        elif "^^StartOfSaftyNetOnlineVerify" in line:
            isCurrentlyReadingReport = True
            tempResultDict = {"is_signature_verified": False}
        elif "Sucessfully verified the signature of the attestation statement" in line:
            tempResultDict["is_signature_verified"] = True
        elif isCurrentlyReadingReport:
            lineContents = line.split(": ")
            tempResultDict[lineContents[0]] = lineContents[1]
    return verificationResultDicts

def is_safetynet_basic_verification_passed(reportDict):
    if not set(["is_signature_verified", "CTS profile match", "Basic integrity match"]).issubset(set(reportDict.keys())):
        return False
    if not reportDict["is_signature_verified"]:
        return False
    if "true" not in reportDict["CTS profile match"]:
        return False
    if "true" not in reportDict["Basic integrity match"]:
        return False
    return True

def mills_to_days_hours_minutes_seconds(inputMills):
    seconds = (inputMills / 1000) % 60
    seconds = int(seconds)
    minutes = (inputMills / (1000 * 60)) % 60
    minutes = int(minutes)
    hours = (inputMills / (1000 * 60 * 60)) % 24
    hours = int(hours)
    days = (inputMills / (1000 * 60 * 60 * 24))
    days = int(days)
    return days, hours, minutes, seconds

def get_safetynet_confidence_level(days, hours, minutes, seconds):
    if days > 0:
        return 30
    if hours > 0:
        return 60
    if minutes > 0:
        return 90
    return 99

def try_get_raw_safetynet_report_str(completeReportsStr, indexToGet):
    tempReportsStr = completeReportsStr
    resultStr = ""
    tempIndex = indexToGet
    while(tempIndex >= 0):
        tempReportStartIndex = tempReportsStr.find("^^StartOfSaftyNetOnlineVerify\n")
        tempReportEndIndex = tempReportsStr.find("^^EndOfSaftyNetOnlineVerify")
        if tempIndex > 0:
            tempReportsStr = tempReportsStr[tempReportEndIndex + len("^^EndOfSaftyNetOnlineVerify"):]
        else:
            resultStr = tempReportsStr[tempReportStartIndex + len("^^StartOfSaftyNetOnlineVerify\n"):tempReportEndIndex]
        tempIndex -= 1
    return resultStr

# def update_with_safetynet_verification(rootUi, status1LabelToBeUpdated, status2LabelToBeUpdated, 
#     status1TEELabelToBeUpdated, status2TEELabelToBeUpdated,
#     statusTimeWindowLabelToBeUpdated, statusConfidenceLevelToBeUpdated,
#     rawReportTextArea1ToBeUpdated, rawReportTextArea2ToBeUpdated):
def update_with_safetynet_verification(rootUi, status1LabelToBeUpdated, status2LabelToBeUpdated, 
    status1TEELabelToBeUpdated, status2TEELabelToBeUpdated,
    rawReportTextArea1ToBeUpdated, rawReportTextArea2ToBeUpdated):
    print("SafetyNet verification start time:", round(time() * 1000000))
    process = subprocess.Popen(
        "cd " + pathToSafetynetVerification + "&&" + cmd4SafetynetVerification + " " + pathFromSafetynetVerification + sys.argv[4] ,
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, shell=True)
    dotCounter = 1
    while process.poll() is None:
        status1LabelToBeUpdated.config(text="Verifying" + "." * dotCounter, fg="yellow")
        status2LabelToBeUpdated.config(text="Verifying" + "." * dotCounter, fg="yellow")
        status1TEELabelToBeUpdated.config(text="Verifying" + "." * dotCounter, fg="yellow")
        status2TEELabelToBeUpdated.config(text="Verifying" + "." * dotCounter, fg="yellow")
        # statusTimeWindowLabelToBeUpdated.config(text="Updating" + "." * dotCounter, fg="yellow")
        # statusConfidenceLevelToBeUpdated.config(text="Updating" + "." * dotCounter, fg="yellow")
        dotCounter = (dotCounter + 1) % 4
        rootUi.update()
        sleep(0.3)
    stdout, stderr = process.communicate()
    verificationResultStr = stdout.decode("utf-8")
    # print("verificationResultStr:", verificationResultStr)
    verificationReportDicts = seperate_safetynet_verification_result_str(verificationResultStr)
    # print("update_with_safetynet_verification:", verificationReportDicts)

    # Update with normal verification status
    if is_safetynet_basic_verification_passed(verificationReportDicts[0]):
        status1LabelToBeUpdated.config(text="Verified!", fg="green")
    else:
        status1LabelToBeUpdated.config(text="Unverified!", fg="red")
    if is_safetynet_basic_verification_passed(verificationReportDicts[1]):
        status2LabelToBeUpdated.config(text="Verified!", fg="green")
    else:
        status2LabelToBeUpdated.config(text="Unverified!", fg="red")

    # Update with TEE verification status
    if "true" in verificationReportDicts[0]["Has HARDWARE_BACKED evaluation type"]:
        status1TEELabelToBeUpdated.config(text="Supported!", fg="green")
    else:
        status1TEELabelToBeUpdated.config(text="Not supported!", fg="red")
    if "true" in verificationReportDicts[1]["Has HARDWARE_BACKED evaluation type"]:
        status2TEELabelToBeUpdated.config(text="Supported!", fg="green")
    else:
        status2TEELabelToBeUpdated.config(text="Not supported!", fg="red")
    
    timeWindowDays, timeWindowHours, timeWindowMinutes, timeWindowSeconds = \
        mills_to_days_hours_minutes_seconds(int(verificationReportDicts[1]["Timestamp"].split()[0]) 
            - int(verificationReportDicts[0]["Timestamp"].split()[0]))
    confidenceLevel = get_safetynet_confidence_level(timeWindowDays, timeWindowHours, timeWindowMinutes, timeWindowSeconds)
    
    # Update with Timewondow and Confidence
    # print("timeWindowDays:", timeWindowDays, ";timeWindowHours:", timeWindowHours, ";timeWindowMinutes:", timeWindowMinutes, ";timeWindowSeconds:", timeWindowSeconds)
    # statusTimeWindowLabelToBeUpdated.config(\
    #     text=str(timeWindowDays) + " days " + str(timeWindowHours) + " hours " + str(timeWindowMinutes) + " minutes " + str(timeWindowSeconds) + " seconds", 
    #     fg="black")
    # if confidenceLevel <= 30:
    #     statusConfidenceLevelToBeUpdated.config(text=str(confidenceLevel) + "%", fg="red")
    #     statusTimeWindowLabelToBeUpdated.config(fg="red")
    # elif confidenceLevel <= 60:
    #     statusConfidenceLevelToBeUpdated.config(text=str(confidenceLevel) + "%", fg="orange")
    #     statusTimeWindowLabelToBeUpdated.config(fg="orange")
    # else:
    #     statusConfidenceLevelToBeUpdated.config(text=str(confidenceLevel) + "%", fg="green")
    #     statusTimeWindowLabelToBeUpdated.config(fg="green")

    rawReportTextArea1ToBeUpdated.configure(state="normal")
    rawReportTextArea2ToBeUpdated.configure(state="normal")
    
    rawReportTextArea1ToBeUpdated.insert(INSERT, try_get_raw_safetynet_report_str(verificationResultStr, 0))
    rawReportTextArea2ToBeUpdated.insert(INSERT, try_get_raw_safetynet_report_str(verificationResultStr, 1))

    rawReportTextArea1ToBeUpdated.configure(state="disabled")
    rawReportTextArea2ToBeUpdated.configure(state="disabled")

    rootUi.update()
    print("SafetyNet verification end time:", round(time() * 1000000))

def play_video():
    process = subprocess.Popen(
        "vlc " + sys.argv[1],
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, shell=True)

def main():

    if len(sys.argv) < 5:
        print("Usage: ./verification_with_gui.py <video_file> <sig_file> <pubkey_file> <metadata_file>")
        return

    gui = Tk()
    gui.geometry("1280x720")
    gui.configure(bg="#b8b8b8")
    gui.title("Vronicle Viewer Verification Demo")

    # Display verification status on the top left
    verificationStatusFrame = Frame(gui, bg="#cfcfcf")
    verificationStatusFrame.grid(row=0, column=0, columnspan=2, padx=40, pady=40)

    # SGX certificate and signature verification
    sgxVerificationLabel = Label(verificationStatusFrame, text="SGX Certificate & Signature Status: ", bg="#cfcfcf")
    sgxVerificationLabel.grid(row=0, column=0, padx=(10, 0), pady=(10, 0))
    sgxVerificationStatusLabel = Label(verificationStatusFrame, text="Awaiting", fg="grey", bg="#cfcfcf")
    sgxVerificationStatusLabel.grid(row=0, column=1, padx=(30, 10), pady=(10, 0))
    gui.after(1000, update_with_sgx_verification, gui, sgxVerificationStatusLabel)

    # Safetynet verification
    safetynetVerificationLabel1 = Label(verificationStatusFrame, text="SafetyNet R1 Verification Status: ", bg="#cfcfcf")
    safetynetVerificationLabel1.grid(row=1, column=0, pady=(10, 0))
    safetynetVerificationIsTEEBasedLabel1 = Label(verificationStatusFrame, text="SafetyNet R1 TEE Support: ", bg="#cfcfcf")
    safetynetVerificationIsTEEBasedLabel1.grid(row=2, column=0, pady=(10, 0))
    safetynetVerificationLabel2 = Label(verificationStatusFrame, text="SafetyNet R2 Verification Status: ", bg="#cfcfcf")
    safetynetVerificationLabel2.grid(row=3, column=0, pady=(10, 0))
    safetynetVerificationIsTEEBasedLabel2 = Label(verificationStatusFrame, text="SafetyNet R1 TEE Support: ", bg="#cfcfcf")
    safetynetVerificationIsTEEBasedLabel2.grid(row=4, column=0, pady=(10, 10))

    safetynetVerificationStatusLabel1 = Label(verificationStatusFrame, text="Awaiting", fg="grey", bg="#cfcfcf")
    safetynetVerificationStatusLabel1.grid(row=1, column=1, padx=(15, 10), pady=(10, 0))
    safetynetVerificationIsTEEBasedStatusLabel1 = Label(verificationStatusFrame, text="Awaiting", fg="grey", bg="#cfcfcf")
    safetynetVerificationIsTEEBasedStatusLabel1.grid(row=2, column=1, padx=(15, 10), pady=(10, 0))
    safetynetVerificationStatusLabel2 = Label(verificationStatusFrame, text="Awaiting", fg="grey", bg="#cfcfcf")
    safetynetVerificationStatusLabel2.grid(row=3, column=1, padx=(15, 10), pady=(10, 0))
    safetynetVerificationIsTEEBasedStatusLabel2 = Label(verificationStatusFrame, text="Awaiting", fg="grey", bg="#cfcfcf")
    safetynetVerificationIsTEEBasedStatusLabel2.grid(row=4, column=1, padx=(15, 10), pady=(10, 10))

    # Display time and confidence status also on the top left; but to the right of verification status
    readableVerificationStatusFrame = Frame(gui, bg="#cfcfcf")
    readableVerificationStatusFrame.grid(row=0, column=1, sticky=W, padx=(0, 40), pady=(40, 10))

    # # Timewindow
    # safetynetTimeWindowLabel = Label(readableVerificationStatusFrame, text="SafetyNet Attestation Time Window: ", bg="#cfcfcf")
    # safetynetTimeWindowLabel.grid(row=0, column=0, padx=(10, 0), pady=(10, 0), sticky=W)
    # safetynetTimeWindowStatusLabel = Label(readableVerificationStatusFrame, text="Awaiting", fg="grey", bg="#cfcfcf")
    # safetynetTimeWindowStatusLabel.grid(row=1, column=0, columnspan=2, padx=(30, 10), pady=(10, 0))

    # # Confidence
    # safetynetConfidenceLabel1 = Label(readableVerificationStatusFrame, text="SafetyNet Confidence Level: ", bg="#cfcfcf")
    # safetynetConfidenceLabel1.grid(row=2, column=0, padx=(10, 0), pady=(10, 0), sticky=W)
    # safetynetConfidenceStatusLabel1 = Label(readableVerificationStatusFrame, text="Awaiting", fg="grey", bg="#cfcfcf")
    # safetynetConfidenceStatusLabel1.grid(row=3, column=0, columnspan=2, padx=(30, 10), pady=(10, 10))

    # Display Safetynet reports in Half-RAW on the bottom left
    safetynetReportsFrame = Frame(gui, bg="#cfcfcf")
    safetynetReportsFrame.grid(row=1, column=0, columnspan=2, sticky=NW, padx=40, pady=(0, 10))

    # Half-Raw safetynet report 1
    safetynetRawReportLabel1 = Label(safetynetReportsFrame, text="SafetyNet Raw Report 1:", bg="#cfcfcf")
    safetynetRawReportLabel1.grid(row=0, column=0, padx=(10, 0), pady=(10, 0), sticky=W)
    safetynetRawReportTextArea1 = st.ScrolledText(safetynetReportsFrame, wrap=WORD, 
                                      width=40, 
                                      height=20, 
                                      font=("Times New Roman", 11),
                                      state="disabled")
    safetynetRawReportTextArea1.grid(row=1, column=0, padx=(10, 0), pady=(10, 10), sticky=W)

    # Half-Raw safetynet report 2
    safetynetRawReportLabel2 = Label(safetynetReportsFrame, text="SafetyNet Raw Report 2:", bg="#cfcfcf")
    safetynetRawReportLabel2.grid(row=0, column=1, padx=(100, 0), pady=(10, 0), sticky=W)
    safetynetRawReportTextArea2 = st.ScrolledText(safetynetReportsFrame, wrap=WORD, 
                                      width=40, 
                                      height=20, 
                                      font=("Times New Roman", 11),
                                      state="disabled")
    safetynetRawReportTextArea2.grid(row=1, column=1, padx=(100, 10), pady=(10, 10), sticky=W)

    # gui.after(2000, update_with_safetynet_verification, gui, 
    #     safetynetVerificationStatusLabel1, safetynetVerificationStatusLabel2,
    #     safetynetVerificationIsTEEBasedStatusLabel1, safetynetVerificationIsTEEBasedStatusLabel2,
    #     safetynetTimeWindowStatusLabel, safetynetConfidenceStatusLabel1,
    #     safetynetRawReportTextArea1, safetynetRawReportTextArea2)
    gui.after(2000, update_with_safetynet_verification, gui, 
        safetynetVerificationStatusLabel1, safetynetVerificationStatusLabel2,
        safetynetVerificationIsTEEBasedStatusLabel1, safetynetVerificationIsTEEBasedStatusLabel2,
        safetynetRawReportTextArea1, safetynetRawReportTextArea2)
    
    # Display metadata in Half-RAW on the right
    metadataFrame = Frame(gui, bg="#cfcfcf")
    metadataFrame.grid(row=0, rowspan=2, column=2, sticky=N, padx=40, pady=(40, 10))

    # Metadata
    metadataFrameLabel = Label(metadataFrame, text="Raw Metadata:", bg="#cfcfcf")
    metadataFrameLabel.grid(row=0, column=0, padx=(10, 0), pady=(10, 0), sticky=W)
    metadataFrameTextArea = st.ScrolledText(metadataFrame, wrap=WORD, 
                                      width=50, 
                                      height=30, 
                                      font=("Times New Roman", 11))
    metadataFrameTextArea.grid(row=1, column=0, padx=10, pady=10, sticky=W)
    with open(sys.argv[4], 'r') as metadataFile:
        parsedMetadataJson = json.loads(metadataFile.read())
        parsedMetadataJson.pop("safetynet_jws", None)
        metadataFrameTextArea.insert(INSERT, json.dumps(parsedMetadataJson, indent=4))
    metadataFrameTextArea.configure(state="disabled")

    # Display some necessary button(s) on the bottom right
    bottomRightButtonsFrame = Frame(gui, bg="#b8b8b8")
    bottomRightButtonsFrame.grid(row=2, column=2, sticky=S, padx=40, pady=(0, 40))

    # Play button
    playButton = Button(bottomRightButtonsFrame, text="Play", width=40, command=play_video)
    playButton.grid()

    gui.mainloop()

if __name__ == "__main__":
    main()