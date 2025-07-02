import 'dart:async';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';

/// NFC error codes and descriptions
enum NfcErrorCode {
  success("00", "Success"),
  nfcDisabled("ND", "NFC disabled"),
  nfcNotSupported("NN", "NFC not supported"),
  cardNotSupported("CN", "Card not supported (Only MIFARE Plus and Desfire cards are supported)"),
  timeout("TO", "Operation timed out"),
  userCancelled("UC", "User cancelled operation"),
  sessionError("SE", "NFC session error"),
  communicationError("CE", "Communication error with card"),
  unknownError("UE", "Unknown error");

  const NfcErrorCode(this.code, this.description);
  
  final String code;
  final String description;
  
  @override
  String toString() => code;
}

/// NFC operation result
class NfcResult {
  final NfcErrorCode code;
  final String? message;
  final dynamic data;
  
  const NfcResult(this.code, {this.message, this.data});
  
  bool get isSuccess => code == NfcErrorCode.success;
  bool get isError => !isSuccess;
  
  @override
  String toString() => 'NfcResult(${code.description}${message != null ? ': $message' : ''})';
}

/// Supported NFC tag types for MIFARE Plus operations
enum SupportedTagType {
  iso7816,
  mifarePlus,
  mifareDesfire,
}

/// Extension to convert NFCTagType to SupportedTagType
extension NFCTagTypeExtension on NFCTagType {
  SupportedTagType? get asSupportedType {
    switch (this) {
      case NFCTagType.iso7816:
        return SupportedTagType.iso7816;
      case NFCTagType.mifare_plus:
        return SupportedTagType.mifarePlus;
      case NFCTagType.mifare_desfire:
        return SupportedTagType.mifareDesfire;
      default:
        return null;
    }
  }
}

/// Checks NFC availability and returns a result object
/// 
/// Returns [NfcResult] with success status and any error information.
/// This should be called before attempting any NFC operations.
/// 
/// The method checks if NFC is available, disabled, or not supported on the device.
/// It provides appropriate error messages for different NFC states.
Future<NfcResult> isNfcAvailable() async {
  try {
    final nfcAvailability = await FlutterNfcKit.nfcAvailability;
    
    switch (nfcAvailability) {
      case NFCAvailability.available:
        return const NfcResult(NfcErrorCode.success);
      case NFCAvailability.disabled:
        return const NfcResult(NfcErrorCode.nfcDisabled, message: "Please enable NFC in your device settings");
      case NFCAvailability.not_supported:
        return const NfcResult(NfcErrorCode.nfcNotSupported, message: "This device does not support NFC");
    }
  } catch (e) {
    return NfcResult(NfcErrorCode.unknownError, message: "Failed to check NFC availability: $e");
  }
}

/// Polls for a supported NFC card and returns a result object
/// 
/// [debugMode] enables debug logging
/// [timeout] the timeout duration in seconds
/// [alertMessage] message shown to user during scanning
/// [multipleTagMessage] message shown when multiple tags are detected
/// 
/// Returns [NfcResult] with card information or error details.
/// This method handles the card detection and validation process.
/// 
/// The method polls for NFC cards and validates that the detected card type is supported.
/// It provides user-friendly messages during the scanning process and handles timeouts.
Future<NfcResult> pollForCard(
  bool debugMode, 
  int timeout, 
  String alertMessage, 
  String multipleTagMessage
) async {
  try {
    debugPrint("Polling for card...", debugMode);

    final nfcTag = await FlutterNfcKit.poll(
      timeout: Duration(seconds: timeout),
      iosMultipleTagMessage: multipleTagMessage,
      iosAlertMessage: alertMessage,
    ).timeout(Duration(seconds: timeout));

    // Validate tag type
    final supportedType = nfcTag.type.asSupportedType;
    if (supportedType == null) {
      debugPrint("Card not supported: ${nfcTag.type}", debugMode);
      return NfcResult(
        NfcErrorCode.cardNotSupported, 
        message: "Card type ${nfcTag.type} is not supported. Only MIFARE Plus and Desfire cards are supported."
      );
    }

    debugPrint("Tag detected: ${nfcTag.type}", debugMode);
    debugPrint("Tag standard: ${nfcTag.standard}", debugMode);
    debugPrint("Tag ID: ${nfcTag.id}", debugMode);

    return NfcResult(NfcErrorCode.success, data: nfcTag);
  } on TimeoutException {
    debugPrint("Card polling timed out", debugMode);
    return const NfcResult(NfcErrorCode.timeout, message: "No card detected within timeout period");
  } catch (e) {
    debugPrint("Error polling for card: $e", debugMode);
    return NfcResult(NfcErrorCode.sessionError, message: "Failed to poll for card: $e");
  }
}

/// Sends a command to the NFC card and returns the response string
/// 
/// [command] the command to send in hex format
/// 
/// Returns the card response as a string.
/// Throws [Exception] if communication fails.
/// 
/// This method validates the command format and sends it to the NFC card using FlutterNfcKit.
/// The command must be a valid hex string for proper transmission.
Future<String> sendCommand(String command) async {
  try {
    if (command.isEmpty) {
      throw ArgumentError('Command cannot be empty');
    }
    
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(command)) {
      throw ArgumentError('Command must be a valid hex string');
    }
    
    final response = await FlutterNfcKit.transceive(command);
    return response;
  } catch (e) {
    throw Exception('Failed to send command: $e');
  }
}

/// Sends multiple commands to the NFC card and returns all responses
/// 
/// [commands] list of commands to send in hex format
/// 
/// Returns a list of responses in the same order as commands.
/// Throws [Exception] if any command fails.
/// 
/// This method sends a sequence of commands to the NFC card and collects all responses.
/// If any command fails, the entire operation fails and throws an exception.
Future<List<String>> sendCommands(List<String> commands) async {
  if (commands.isEmpty) {
    throw ArgumentError('Commands list cannot be empty');
  }
  
  final responses = <String>[];
  
  for (int i = 0; i < commands.length; i++) {
    try {
      final response = await sendCommand(commands[i]);
      responses.add(response);
    } catch (e) {
      throw Exception('Failed to send command ${i + 1}: $e');
    }
  }
  
  return responses;
}

/// Validates a card response for success status
/// 
/// [response] the card response to validate
/// [successCode] the expected success code (default: "90")
/// 
/// Returns true if the response indicates success, false otherwise.
/// 
/// This method checks if a card response starts with the expected success code.
/// It's commonly used to validate NFC command responses before processing data.
bool isSuccessfulResponse(String response, {String successCode = "90"}) {
  if (response.isEmpty) return false;
  return response.startsWith(successCode);
}

/// Extracts error code from card response
/// 
/// [response] the card response
/// 
/// Returns the error code (first 2 characters) or empty string if response is invalid.
/// 
/// This method extracts the first two characters from a card response, which typically
/// represent the status code or error code in NFC protocols.
String extractErrorCode(String response) {
  if (response.isEmpty || response.length < 2) return "";
  return response.substring(0, 2);
}

/// Extracts data from card response (removes status code)
/// 
/// [response] the card response
/// 
/// Returns the data portion of the response (everything after the status code).
/// 
/// This method removes the status code (first two characters) from a card response
/// and returns the remaining data portion for further processing.
String extractResponseData(String response) {
  if (response.isEmpty || response.length < 2) return "";
  return response.substring(2);
}

/// Prints debug messages if debugMode is true
/// 
/// [message] the message to print
/// [debugMode] whether debug mode is enabled
/// 
/// This method provides conditional debug logging with timestamps.
/// Messages are only printed when debugMode is enabled to avoid console spam.
void debugPrint(String message, bool debugMode) {
  if (debugMode) {
    print('[${DateTime.now().toIso8601String()}] $message');
  }
}

/// Prints debug messages with log level if debugMode is true
/// 
/// [message] the message to print
/// [debugMode] whether debug mode is enabled
/// [level] the log level (INFO, WARNING, ERROR)
/// 
/// This method provides conditional debug logging with timestamps and log levels.
/// Messages are only printed when debugMode is enabled and include the specified log level.
void debugPrintWithLevel(String message, bool debugMode, {String level = 'INFO'}) {
  if (debugMode) {
    print('[${DateTime.now().toIso8601String()}][$level] $message');
  }
}

/// Gets a human-readable description of NFC tag type
/// 
/// [tagType] the NFC tag type
/// 
/// Returns a descriptive string for the tag type.
/// 
/// This method converts NFCTagType enum values to human-readable descriptions
/// for user interfaces and logging purposes.
String getTagTypeDescription(NFCTagType tagType) {
  switch (tagType) {
    case NFCTagType.iso7816:
      return "ISO 7816 Smart Card";
    case NFCTagType.mifare_plus:
      return "MIFARE Plus";
    case NFCTagType.mifare_desfire:
      return "MIFARE DESFire";
    case NFCTagType.mifare_ultralight:
      return "MIFARE Ultralight";
    case NFCTagType.mifare_classic:
      return "MIFARE Classic";
    case NFCTagType.iso15693:
      return "ISO 15693";
    case NFCTagType.iso18092:
      return "ISO 18092";
    case NFCTagType.webusb:
      return "WebUSB";
    case NFCTagType.unknown:
      return "Unknown";
  }
}