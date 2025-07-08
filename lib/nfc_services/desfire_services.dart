import 'dart:async';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';

import 'shared/crypto_utilities.dart';
import 'shared/nfc_utilities.dart';

/// Constants for DESFire operations
class DesfireConstants {
  static const int timeout = 7;
  static const String successStatus = '9100';
  static const String additionalFrameStatus = '91AF';
  static const String nfcSuccessCode = '90';
  static const int aesKeySize = 16;
  static const int aesBlockSize = 16;
  static const int randomSize = 16;
  static const int keyHexLength = 32;
  static const int applicationIdLength = 6;
  static const int maxRetryAttempts = 1;
}

/// Error codes for DESFire operations
enum DesfireErrorCode {
  success("00", "Success"),

  invalidApplicationId("DAID", "Invalid application ID (must be 6 hex characters)"),
  invalidFileId("DFID", "Invalid file ID"),
  invalidKeyNumber("DKN", "Invalid key number"),
  invalidAuthKey("DAK", "Invalid authentication key (must be 32 hex characters)"),
  timeoutError("DT", "Operation timed out"),
  nfcUnavailable("DN", "NFC is not available"),
  sessionError("DSN", "NFC session error"),
  unexpectedState("DU", "Unexpected application state"),
  userCancelled("DUC", "User cancelled operation"),
  cardError("CARD", "Card error"),
  authenticationFailed("DAF", "Authentication failed"),
  sessionKeyError("DSE", "Session key generation failed"),
  cmacError("DCM", "CMAC calculation failed"),
  dataDecryptionError("DDD", "Data decryption failed"),
  invalidResponse("DIR", "Invalid card response"),
  cardConnectionLost("DCCL", "Card connection lost - please keep card steady"),
  communicationError("DCE", "Communication error with card"),
  applicationNotFound("DANF", "Application not found"),
  fileNotFound("DFNF", "File not found"),
  permissionDenied("DPD", "Permission denied"),
  conditionsNotSatisfied("DCNS", "Conditions of use not satisfied - The current command code not available at current card state"),
  unknownError("UE", "Unknown error. Try again");

  const DesfireErrorCode(this.code, this.description);
  final String code;
  final String description;
  @override
  String toString() => code;
}

/// Maps DESFire error codes to descriptive messages
const Map<String, String> desfireErrorCodeMap = {
  "00": "Success",
  "0B": "Conditions of use not satisfied - The current command code not available at current card state",
  "0C": "No change",
  "0E": "Out of EEPROM",
  "1C": "Illegal command",
  "1E": "Integrity error",
  "40": "No such key",
  "6E": "Error (ISO)",
  "7E": "Length error",
  "97": "Crypto error",
  "9D": "Permission denied",
  "9E": "Parameter error",
  "A0": "Application not found",
  "AE": "Authentication error",
  "AF": "Additional frame",
  "BE": "Boundary error",
  "C1": "Card integrity error",
  "CA": "Command aborted",
  "CD": "Card disabled",
  "CE": "Count error",
  "DE": "Duplicate error",
  "EE": "EEPROM error",
  "F0": "File not found",
  "F1": "File integrity error",
  // Additional common DESFire error codes
  "91A0": "Application not found",
  "91AE": "Authentication error",
  "91AF": "Additional frame",
  "91BE": "Boundary error",
  "91C1": "Card integrity error",
  "91CA": "Command aborted",
  "91CD": "Card disabled",
  "91CE": "Count error",
  "91DE": "Duplicate error",
  "91EE": "EEPROM error",
  "91F0": "File not found",
  "91F1": "File integrity error",
  "91F5": "File not found",
  "91F6": "File not found",
  "91F7": "File not found",
  "91F8": "File not found",
  "91F9": "File not found",
  "91FA": "File not found",
  "91FB": "File not found",
  "91FC": "File not found",
  "91FD": "File not found",
  "91FE": "File not found",
  "91FF": "File not found",
};

/// Sealed class for consistent result handling
sealed class DesfireResult<T> {
  const DesfireResult();
  
  bool get isSuccess => this is DesfireSuccess<T>;
  DesfireErrorCode? get errorCode => this is DesfireError<T> ? (this as DesfireError<T>).error : null;
  T? get data => this is DesfireSuccess<T> ? (this as DesfireSuccess<T>).data : null;
}

class DesfireError<T> extends DesfireResult<T> {
  /// Creates a DesfireError with an optional message and exception for debugging.
  const DesfireError(this.error, {this.message, this.exception});
  final DesfireErrorCode error;
  final String? message;
  final Object? exception;
  @override
  String toString() => 'DesfireError(${error.description}${message != null ? ': $message' : ''}${exception != null ? ' Exception: $exception' : ''})';
}

class DesfireSuccess<T> extends DesfireResult<T> {
  const DesfireSuccess(this.data);
  final T data;
  @override
  String toString() => 'DesfireSuccess($data)';
}

/// Result of DESFire authentication operation
class DesfireAuthResult {
  const DesfireAuthResult({
    required this.code,
    required this.randomB,
    required this.randomA,
    required this.sessionKey,
    this.description = "",
  });

  final String code;  
  final String randomB;
  final String randomA;
  final String sessionKey;
  final String description;
}

/// File settings for DESFire operations
class DesfireFileSettings {
  const DesfireFileSettings({
    required this.fileType,
    required this.communicationType,
    required this.accessRights,
    required this.rawResponse,
  });

  final String fileType;
  final String communicationType;
  final String accessRights;
  final String rawResponse;
}

/// Result of first DESFire authentication step
class DesfireFirstAuthResult {
  const DesfireFirstAuthResult({
    required this.decryptedRandomB,
    required this.encryptedRandomB,
  });

  final Uint8List decryptedRandomB;
  final String encryptedRandomB;
}



/// Main DESFire service for authentication and data reading
class DesfireNfcServices {
  final bool debugMode;
  final int timeout;
  final String alertMessage;
  final String multipleTagMessage;

  /// Creates a new DesfireNfcServices instance
  /// 
  /// [debugMode] enables detailed logging of operations
  /// [timeout] specifies the NFC operation timeout in seconds
  /// [alertMessage] message shown to user during NFC scanning
  /// [multipleTagMessage] message shown when multiple tags are detected
  DesfireNfcServices({
    this.debugMode = false,
    this.timeout = DesfireConstants.timeout,
    this.alertMessage = "Scan your DESFire card",
    this.multipleTagMessage = "Multiple tags found!"
  });

  /// Prints debug messages with log level if debugMode is true
  void _log(String message, {String level = 'INFO'}) {
    if (debugMode) {
      print('[${DateTime.now().toIso8601String()}][$level] $message');
    }
  }

  /// Validates input parameters for DESFire operations
  /// 
  /// [applicationId] the application ID in hex format (6 characters)
  /// [fileId] the file ID in hex format (0-31)
  /// [keyNumber] the key number in hex format (0-13)
  /// [authKey] the authentication key in hex format (32 characters)
  /// 
  /// Returns [DesfireErrorCode.success] if validation passes, otherwise returns
  /// the appropriate error code with description.
  /// 
  /// This method validates all input parameters for DESFire read operations,
  /// ensuring they meet the required format and length constraints.
  DesfireErrorCode _validateDesfireReadParameters(
    String applicationId,
    String fileId,
    String keyNumber,
    String authKey,
  ) {
    ArgumentError.checkNotNull(applicationId, 'applicationId');
    ArgumentError.checkNotNull(fileId, 'fileId');
    ArgumentError.checkNotNull(keyNumber, 'keyNumber');
    ArgumentError.checkNotNull(authKey, 'authKey');

    // Validate applicationId (6 hex characters)
    if (applicationId.length != DesfireConstants.applicationIdLength) {
      return DesfireErrorCode.invalidApplicationId;
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(applicationId)) {
      return DesfireErrorCode.invalidApplicationId;
    }

    // Validate fileId (0-31 as integer string)
    if (fileId.isEmpty) {
      return DesfireErrorCode.invalidFileId;
    }
    if (!RegExp(r'^[0-9]+$').hasMatch(fileId)) {
      return DesfireErrorCode.invalidFileId;
    }
    final fileIdInt = int.tryParse(fileId);
    if (fileIdInt == null || fileIdInt < 0 || fileIdInt > 31) {
      return DesfireErrorCode.invalidFileId;
    }

    // Validate keyNumber (0-13 as integer string)
    if (keyNumber.isEmpty) {
      return DesfireErrorCode.invalidKeyNumber;
    }
    if (!RegExp(r'^[0-9]+$').hasMatch(keyNumber)) {
      return DesfireErrorCode.invalidKeyNumber;
    }
    final keyNumberInt = int.tryParse(keyNumber);
    if (keyNumberInt == null || keyNumberInt < 0 || keyNumberInt > 13) {
      return DesfireErrorCode.invalidKeyNumber;
    }

    // Validate authKey (32 hex characters)
    if (authKey.length != DesfireConstants.keyHexLength) {
      return DesfireErrorCode.invalidAuthKey;
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(authKey)) {
      return DesfireErrorCode.invalidAuthKey;
    }
    return DesfireErrorCode.success;
  }

  /// Helper to get DESFire error message from code
  /// 
  /// [code] the DESFire error code (2 or 4 character hex string)
  /// 
  /// Returns a human-readable error message for the given error code.
  /// 
  /// This method maps DESFire error codes to descriptive messages
  /// for better error reporting and debugging.
  String _getDesfireErrorMessage(String code) {
    return desfireErrorCodeMap[code] ?? "Unknown error code: $code";
  }

  /// Validates card response format and status
  /// 
  /// [response] the card response to validate
  /// [expectedMinLength] the minimum expected response length
  /// [expectedStatus] the expected success status code
  /// 
  /// Throws [CryptoException] if validation fails.
  /// 
  /// This method validates DESFire card responses, handling both short error codes
  /// (like "0B") and longer responses with status codes. It ensures responses
  /// meet length requirements and have the expected success status.
  void _validateCardResponse(String response, int expectedMinLength, String expectedStatus) {
    // Handle short error responses (2 characters like "0B")
    if (response.length == 2) {
      final errorMessage = _getDesfireErrorMessage(response);
      throw CryptoException("Card operation failed: $errorMessage");
    }
    
    if (response.length < expectedMinLength) {
      throw CryptoException(
        "Card response too short: expected at least $expectedMinLength characters, got ${response.length}",
      );
    }
    
    if (!response.toUpperCase().endsWith(expectedStatus.toUpperCase())) {
      final actualStatus = response.length >= 4 ? response.substring(response.length - 4) : response;
      final errorMessage = _getDesfireErrorMessage(actualStatus);
      throw CryptoException("Card operation failed: $errorMessage");
    }
  }

  /// Selects the DESFire application
  /// 
  /// [applicationId] the application ID in hex format (6 characters)
  /// 
  /// Returns selection result or error.
  /// 
  /// This method sends the SELECT APPLICATION command (5Ah) to the DESFire card
  /// to select the specified application. It handles various error conditions
  /// including application not found and conditions not satisfied.
  Future<DesfireResult<void>> _selectApplication(String applicationId) async {
    try {
      final selectCommand = "905A000003${applicationId}00";
      _log("Selecting application: $selectCommand", level: 'INFO');
      
      final response = await sendCommand(selectCommand);
      _log("Application selection response: $response", level: 'INFO');
      
      // Check for specific error codes
      if (response.toUpperCase().endsWith('91A0')) {
        _log("Application not found on card: $applicationId", level: 'WARNING');
        return DesfireError<void>(DesfireErrorCode.applicationNotFound, message: "Application $applicationId not found on this card");
      }
      
      if (response == '0B') {
        _log("Conditions of use not satisfied for application: $applicationId", level: 'WARNING');
        return DesfireError<void>(DesfireErrorCode.conditionsNotSatisfied, message: "Conditions of use not satisfied - The current command code not available at current card state");
      }
      
      _validateCardResponse(response, 4, DesfireConstants.successStatus);
      
      _log("Application selected successfully", level: 'INFO');
      return const DesfireSuccess(null);
    } catch (e) {
      final errorMessage = e.toString().toLowerCase();
      if (errorMessage.contains('tag was lost') || 
          errorMessage.contains('connection') ||
          errorMessage.contains('communication error')) {
        _log("Card connection lost during application selection: $e", level: 'ERROR');
        return DesfireError<void>(DesfireErrorCode.cardConnectionLost, message: "Card connection lost - please keep card steady", exception: e);
      }
      _log("Application selection error: $e", level: 'ERROR');
      return DesfireError<void>(DesfireErrorCode.communicationError, message: "Communication error with card", exception: e);
    }
  }

  /// Gets file settings for the specified file
  /// 
  /// [fileId] the file ID in hex format
  /// 
  /// Returns file settings or error.
  /// 
  /// This method sends the GET FILE SETTINGS command (F5h) to retrieve
  /// the file configuration including file type, communication type,
  /// and access rights for the specified file.
  Future<DesfireResult<DesfireFileSettings>> _getFileSettings(String fileId) async {
    try {
      final fileIdInt = int.parse(fileId, radix: 16);
      final fileIdHex = fileIdInt.toRadixString(16).padLeft(2, '0');
      
      final command = "90F5000001${fileIdHex}00";
      _log("Getting file settings: $command", level: 'INFO');
      
      final response = await sendCommand(command);
      _log("File settings response: $response", level: 'INFO');
      
      _validateCardResponse(response, 14, DesfireConstants.successStatus);
      
      final responseData = response.substring(0, response.length - 4);
      
      if (responseData.length < 8) {
        throw CryptoException("Insufficient file settings data: $responseData");
      }
      
      final settings = DesfireFileSettings(
        fileType: responseData.substring(0, 2),
        communicationType: responseData.substring(2, 4),
        accessRights: responseData.substring(4, 8),
        rawResponse: response,
      );
      
      _log("File settings: ${settings.fileType}, ${settings.communicationType}, ${settings.accessRights}", level: 'INFO');
      return DesfireSuccess(settings);
    } catch (e) {
      final errorMessage = e.toString().toLowerCase();
      if (errorMessage.contains('tag was lost') || 
          errorMessage.contains('connection') ||
          errorMessage.contains('communication error')) {
        _log("Card connection lost during file settings retrieval: $e", level: 'ERROR');
        return DesfireError<DesfireFileSettings>(DesfireErrorCode.cardConnectionLost, message: "Card connection lost - please keep card steady", exception: e);
      }
      _log("File settings error: $e", level: 'ERROR');
      return DesfireError<DesfireFileSettings>(DesfireErrorCode.communicationError, message: "Communication error with card", exception: e);
    }
  }

  /// Processes the first authentication step
  /// 
  /// [keyNumber] the key number in hex format
  /// [authKey] the authentication key in hex format (32 characters)
  /// 
  /// Returns first authentication result with decrypted RandomB or error.
  /// 
  /// This method sends the first authentication command (AAh) to the card,
  /// receives the encrypted RandomB, and decrypts it using the provided key.
  /// It handles various error conditions and connection issues.
  Future<DesfireResult<DesfireFirstAuthResult>> _processFirstAuthStep(String keyNumber, String authKey) async {
    try {
      // Ensure keyNumber is properly formatted as 2 hex characters
      final formattedKeyNumber = keyNumber.padLeft(2, '0');
      final authCommand = "90AA000001${formattedKeyNumber}00";
      _log("Sending authentication command: $authCommand", level: 'INFO');
      
      final response = await sendCommand(authCommand);
      _log("Authentication response: $response", level: 'INFO');
      
      _validateCardResponse(response, 36, DesfireConstants.additionalFrameStatus);
      
      final encryptedRandomB = response.substring(0, 32);
      final encryptedRandomBBytes = Uint8List.fromList(hex.decode(encryptedRandomB));
      
      final decryptedRandomB = CryptoUtilities.aesDecrypt(
        encryptedRandomB,
        authKey,
        "00000000000000000000000000000000"
      );
      
      _log("Decrypted RandomB: ${hex.encode(decryptedRandomB)}", level: 'INFO');
      return DesfireSuccess(DesfireFirstAuthResult(
        decryptedRandomB: decryptedRandomB,
        encryptedRandomB: encryptedRandomB,
      ));
    } catch (e) {
      final errorMessage = e.toString().toLowerCase();
      if (errorMessage.contains('tag was lost') || 
          errorMessage.contains('connection') ||
          errorMessage.contains('communication error')) {
        _log("Card connection lost during first auth step: $e", level: 'ERROR');
        return DesfireError<DesfireFirstAuthResult>(DesfireErrorCode.cardConnectionLost, message: "Card connection lost - please keep card steady", exception: e);
      }
      _log("Authentication failed: $e", level: 'ERROR');
      return DesfireError<DesfireFirstAuthResult>(DesfireErrorCode.authenticationFailed, exception: e);
    }
  }

  /// Processes the second authentication step
  /// 
  /// [firstAuthResult] the result from the first authentication step
  /// [authKey] the authentication key in hex format (32 characters)
  /// [attempt] current retry attempt number
  /// 
  /// Returns complete authentication result with session key or error.
  /// 
  /// This method sends the second authentication command (AFh) to the card,
  /// which includes the encrypted RandomA + rotated RandomB. It validates
  /// the card's response and generates the session key for subsequent operations.
  Future<DesfireResult<DesfireAuthResult>> _processSecondAuthStep(
    DesfireFirstAuthResult firstAuthResult, 
    String authKey, 
    int attempt
  ) async {
    try {
      final randomA = CryptoUtilities.generateSecureRandom(DesfireConstants.randomSize);
      _log("Generated RandomA: ${hex.encode(randomA)}", level: 'INFO');
      
      final rotatedRandomB = CryptoUtilities.rotateLeft(firstAuthResult.decryptedRandomB);
      _log("Rotated RandomB: ${hex.encode(rotatedRandomB)}", level: 'INFO');
      
      final randomARandomB = Uint8List.fromList([...randomA, ...rotatedRandomB]);
      _log("Combined RandomA + Rotated RandomB: ${hex.encode(randomARandomB)}", level: 'INFO');
      
      final encryptedResponse = CryptoUtilities.aesEncrypt(
        hex.encode(randomARandomB),
        authKey,
        firstAuthResult.encryptedRandomB
      );
      
      final responseCommand = "90AF000020${hex.encode(encryptedResponse).toUpperCase()}00";
      _log("Sending second authentication command: $responseCommand", level: 'INFO');
      
      final cardResponse = await sendCommand(responseCommand);
      _log("Second authentication response: $cardResponse", level: 'INFO');
      
      _validateCardResponse(cardResponse, 36, DesfireConstants.successStatus);
      
      // Verify card's response
      final encryptedRandomAPrime = cardResponse.substring(0, 32);
      final encryptedRandomAPrimeBytes = Uint8List.fromList(hex.decode(encryptedRandomAPrime));
      
      final ivBytes = encryptedResponse.sublist(16, 32);
      _log("Decrypting card response with:", level: 'INFO');
      _log("  data: $encryptedRandomAPrime", level: 'INFO');
      _log("  key: $authKey", level: 'INFO');
      _log("  iv:  ${hex.encode(ivBytes)}", level: 'INFO');
      final rotatedRandomA = CryptoUtilities.aesDecrypt(
        encryptedRandomAPrime,
        authKey,
        hex.encode(ivBytes)
      );
      
      final expectedRotatedRandomA = CryptoUtilities.rotateLeft(randomA);
      
      if (!_verifyRotatedRandomA(rotatedRandomA, expectedRotatedRandomA)) {
        _log("Authentication failed: RandomA verification mismatch", level: 'WARNING');
        return DesfireError<DesfireAuthResult>(DesfireErrorCode.authenticationFailed);
      }
      
      // Generate session key
      final sessionKey = _generateSessionKey(randomA, firstAuthResult.decryptedRandomB);
      _log("Session key generated: ${hex.encode(sessionKey)}", level: 'INFO');
      
      final authResult = DesfireAuthResult(
        code: DesfireErrorCode.success.code,
        randomB: firstAuthResult.encryptedRandomB,
        randomA: hex.encode(randomA),
        sessionKey: hex.encode(sessionKey),
      );
      
      _log("Authentication successful", level: 'INFO');
      return DesfireSuccess(authResult);
    } catch (e) {
      final errorMessage = e.toString().toLowerCase();
      if (errorMessage.contains('tag was lost') || 
          errorMessage.contains('connection') ||
          errorMessage.contains('communication error')) {
        _log("Card connection lost during second auth step: $e", level: 'ERROR');
        return DesfireError<DesfireAuthResult>(DesfireErrorCode.cardConnectionLost, message: "Card connection lost - please keep card steady", exception: e);
      }
      _log("Authentication error: $e", level: 'ERROR');
      return DesfireError<DesfireAuthResult>(DesfireErrorCode.authenticationFailed, exception: e);
    }
  }

  /// Authenticates with the selected DESFire application using AES
  /// 
  /// [authKey] the authentication key in hex format (32 characters)
  /// [keyNumber] the key number in hex format
  /// [attempt] current retry attempt (0-based)
  /// 
  /// Returns authentication result with session key or error.
  /// 
  /// This method orchestrates the complete DESFire authentication process,
  /// including both authentication steps and retry logic. It generates RandomA,
  /// processes both authentication phases, and returns the complete authentication result.
  Future<DesfireResult<DesfireAuthResult>> _authenticateWithApplication(
    String authKey, 
    String keyNumber, {
    int attempt = 0,
  }) async {
    try {
      _log("Starting DESFire authentication with key number: $keyNumber", level: 'INFO');
      
      // Step 1: First authentication step
      final firstStepResult = await _processFirstAuthStep(keyNumber, authKey);
      if (!firstStepResult.isSuccess) {
        return DesfireError<DesfireAuthResult>(firstStepResult.errorCode!, message: (firstStepResult as DesfireError<DesfireFirstAuthResult>).message, exception: (firstStepResult as DesfireError<DesfireFirstAuthResult>).exception);
      }
      
      final firstAuthResult = firstStepResult.data!;
      
      // Step 2: Second authentication step
      final secondStepResult = await _processSecondAuthStep(firstAuthResult, authKey, attempt);
      if (!secondStepResult.isSuccess) {
        // Retry logic
        if (attempt < DesfireConstants.maxRetryAttempts) {
          _log("Retrying authentication (attempt ${attempt + 1})", level: 'INFO');
          return await _authenticateWithApplication(authKey, keyNumber, attempt: attempt + 1);
        }
        return secondStepResult;
      }
      
      return secondStepResult;
    } catch (e) {
      _log("Authentication error: $e", level: 'ERROR');
      return DesfireError<DesfireAuthResult>(DesfireErrorCode.authenticationFailed, exception: e);
    }
  }

  /// Reads encrypted data from the file
  /// 
  /// [fileId] the file ID in hex format
  /// [sessionKey] the session key from authentication
  /// [fileSettings] the file settings retrieved earlier
  /// 
  /// Returns the read data as a hex string or error.
  /// 
  /// This method sends the READ DATA command (BDh) to read data from the file.
  /// It handles both encrypted and plaintext communication modes based on
  /// the file settings, and decrypts the data if necessary.
  Future<DesfireResult<String>> _readEncryptedData(
    String fileId,
    String sessionKey,
    DesfireFileSettings fileSettings,
  ) async {
    try {
      final fileIdInt = int.parse(fileId, radix: 16);
      
      final offsetHex = _to3ByteLEHex(0);
      final lengthHex = _to3ByteLEHex(16);
      final fileIdHex = fileIdInt.toRadixString(16).padLeft(2, '0');

      final readCommand = "90BD000007${fileIdHex}${offsetHex}${lengthHex}00";
      _log("Reading data: $readCommand", level: 'INFO');
      
      final readResponse = await sendCommand(readCommand);
      _log("Read response: $readResponse", level: 'INFO');
      
      if (readResponse.length < 6) {
        throw CryptoException("Invalid read response length: $readResponse");
      }
      
      final responseData = Uint8List.fromList(
        hex.decode(readResponse.substring(0, readResponse.length - 4))
      );
      
      String decryptedData;
      if (fileSettings.communicationType == '03') {
        decryptedData = await _decryptFileData(
          responseData, sessionKey, fileIdHex, offsetHex, lengthHex,
        );
      } else {
        decryptedData = hex.encode(responseData).toUpperCase();
      }
      
      _log("Data read successfully: $decryptedData", level: 'INFO');
      return DesfireSuccess(decryptedData.substring(0, 32));
    } catch (e) {
      final errorMessage = e.toString().toLowerCase();
      if (errorMessage.contains('tag was lost') || 
          errorMessage.contains('connection') ||
          errorMessage.contains('communication error')) {
        _log("Card connection lost during data read: $e", level: 'ERROR');
        return DesfireError<String>(DesfireErrorCode.cardConnectionLost, message: "Card connection lost - please keep card steady", exception: e);
      }
      _log("Data read error: $e", level: 'ERROR');
      return DesfireError<String>(DesfireErrorCode.communicationError, message: "Communication error with card", exception: e);
    }
  }

  /// Decrypts file data using session key and CMAC-derived IV
  /// 
  /// [responseData] the encrypted response data from the card
  /// [sessionKey] the session key in hex format
  /// [fileIdHex] the file ID in hex format
  /// [offsetHex] the offset in 3-byte little-endian hex format
  /// [lengthHex] the length in 3-byte little-endian hex format
  /// 
  /// Returns the decrypted data as a hex string.
  /// 
  /// This method decrypts file data using the session key and a CMAC-derived
  /// initialization vector. The IV is computed from the command data using
  /// the session key for secure communication.
  Future<String> _decryptFileData(
    Uint8List responseData,
    String sessionKey,
    String fileIdHex,
    String offsetHex,
    String lengthHex,
  ) async {
    final commandData = "BD${fileIdHex}${offsetHex}${lengthHex}";
    
    final iv = CryptoUtilities.computeAesCmac(sessionKey, commandData, 128);
    final ivBytes = Uint8List.fromList(hex.decode(iv));
    
    _log("Decrypting with IV: $iv", level: 'INFO');
    
    final decryptedData = CryptoUtilities.aesDecrypt(
      hex.encode(responseData),
      sessionKey,
      hex.encode(ivBytes)
    );
    
    return hex.encode(decryptedData).toUpperCase();
  }

  /// Verifies rotated RandomA using constant-time comparison
  /// 
  /// [received] the received rotated RandomA from the card
  /// [expected] the expected rotated RandomA calculated locally
  /// 
  /// Returns true if verification succeeds, false otherwise.
  /// 
  /// This method performs a constant-time comparison of the rotated RandomA
  /// values to prevent timing attacks during authentication verification.
  bool _verifyRotatedRandomA(Uint8List received, Uint8List expected) {
    if (received.length != expected.length) {
      _log('RandomA length mismatch: ${received.length} vs ${expected.length}', level: 'WARNING');
      return false;
    }
    
    int result = 0;
    for (int i = 0; i < received.length; i++) {
      result |= received[i] ^ expected[i];
    }
    
    final isValid = result == 0;
    _log(isValid ? 'RandomA verified' : 'RandomA verification failed', level: isValid ? 'INFO' : 'WARNING');
    
    return isValid;
  }

  /// Generates session key from RandomA and RandomB
  /// 
  /// [randomA] the generated RandomA from authentication
  /// [randomB] the decrypted RandomB from authentication
  /// 
  /// Returns the generated session key as a byte array.
  /// 
  /// This method generates the session key using the DESFire key derivation
  /// algorithm, combining parts of RandomA and RandomB to create a 16-byte key
  /// for subsequent encrypted communications.
  Uint8List _generateSessionKey(Uint8List randomA, Uint8List randomB) {
    final sessionKey = Uint8List(16);
    sessionKey.setRange(0, 4, randomA, 0);
    sessionKey.setRange(4, 8, randomB, 0);
    sessionKey.setRange(8, 12, randomA, 12);
    sessionKey.setRange(12, 16, randomB, 12);
    return sessionKey;
  }


  /// Converts integer to 3-byte little-endian hex string
  /// 
  /// [value] the integer to convert
  /// 
  /// Throws [ArgumentError] if value is not between 0 and 0xFFFFFF.
  /// Returns the 3-byte little-endian hex string.
  /// 
  /// This method is used for formatting DESFire command parameters
  /// that require 3-byte little-endian values (offset and length).
  String _to3ByteLEHex(int value) {
    if (value < 0 || value > 0xFFFFFF) {
      throw ArgumentError('Value must be between 0 and 0xFFFFFF, got: $value');
    }
    
    return [
      (value & 0xFF).toRadixString(16).padLeft(2, '0'),
      ((value >> 8) & 0xFF).toRadixString(16).padLeft(2, '0'),
      ((value >> 16) & 0xFF).toRadixString(16).padLeft(2, '0'),
    ].join();
  }

  /// Main method for DESFire read operations
  /// 
  /// [applicationId] the application ID as hex string (6 characters)
  /// [fileId] the file ID as hex string
  /// [keyNumber] the key number as hex string
  /// [authKey] the authentication key as hex string (32 characters)
  /// 
  /// Returns DesfireResult<String> with block data or error.
  /// 
  /// This method performs a complete DESFire read operation including:
  /// - Parameter validation
  /// - NFC availability check
  /// - Card polling and detection
  /// - Application selection
  /// - File settings retrieval
  /// - Authentication with the application
  /// - Data reading and decryption
  /// - Session cleanup
  /// 
  /// The method handles all error conditions and provides detailed logging
  /// when debug mode is enabled.
  Future<DesfireResult<String>> readDesfire(
    String applicationId,
    String fileId,
    String keyNumber,
    String authKey,
  ) async {
    try {
      _log("Starting DESFire read operation", level: 'INFO');
      _log("Input parameters - AppID: $applicationId, FileID: $fileId, KeyNum: $keyNumber", level: 'INFO');
      _log("Authentication key: $authKey", level: 'INFO');

      // Validate parameters
      final validationResult = _validateDesfireReadParameters(
        applicationId, fileId, keyNumber, authKey
      );
      if (validationResult != DesfireErrorCode.success) {
        _log("[${validationResult.code}] ${validationResult.description}", level: 'WARNING');
        return DesfireError<String>(validationResult, message: validationResult.description);
      }
      _log("Parameter validation passed", level: 'INFO');

      // Check NFC availability
      _log("Checking NFC availability", level: 'INFO');
      final nfcStatus = await isNfcAvailable();
      if (nfcStatus.code.code != NfcErrorCode.success.code) {
        _log("[${nfcStatus.code}] ${nfcStatus.message ?? ''}", level: 'ERROR');
        return DesfireError<String>(DesfireErrorCode.nfcUnavailable, message: nfcStatus.message);
      }
      _log("NFC is available", level: 'INFO');

      // Poll for card
      _log("Polling for NFC card", level: 'INFO');
      final cardInfo = await pollForCard(debugMode, timeout, alertMessage, multipleTagMessage);
      if (cardInfo.code.code != NfcErrorCode.success.code) {
        _log("[${cardInfo.code}] ${cardInfo.message ?? ''}", level: 'ERROR');
        return DesfireError<String>(DesfireErrorCode.sessionError, message: cardInfo.message);
      }
      _log("NFC card detected", level: 'INFO');

      // Select application
      _log("Selecting application", level: 'INFO');
      final selectResult = await _selectApplication(applicationId);
      if (!selectResult.isSuccess) {
        _log("[${selectResult.errorCode?.code}] ${selectResult.errorCode?.description}", level: 'ERROR');
        final error = selectResult as DesfireError<void>;
        
        if (error.error == DesfireErrorCode.cardConnectionLost) {
          return DesfireError<String>(DesfireErrorCode.cardConnectionLost, message: error.message, exception: error.exception);
        }
        
        return DesfireError<String>(error.error, message: error.message, exception: error.exception);
      }
      _log("Application selected", level: 'INFO');

      // Get file settings
      _log("Getting file settings", level: 'INFO');
      final fileSettingsResult = await _getFileSettings(fileId);
      if (!fileSettingsResult.isSuccess) {
        _log("[${fileSettingsResult.errorCode?.code}] ${fileSettingsResult.errorCode?.description}", level: 'ERROR');
        final error = fileSettingsResult as DesfireError<DesfireFileSettings>;
        
        if (error.error == DesfireErrorCode.cardConnectionLost) {
          return DesfireError<String>(DesfireErrorCode.cardConnectionLost, message: error.message, exception: error.exception);
        }
        
        return DesfireError<String>(error.error, message: error.message, exception: error.exception);
      }
      _log("File settings retrieved", level: 'INFO');

      // Authenticate with application
      _log("Authenticating with application", level: 'INFO');
      final authResult = await _authenticateWithApplication(authKey, keyNumber);
      if (!authResult.isSuccess) {
        _log("[${authResult.errorCode?.code}] ${authResult.errorCode?.description}", level: 'ERROR');
        final error = authResult as DesfireError<DesfireAuthResult>;
        
        if (error.error == DesfireErrorCode.cardConnectionLost) {
          return DesfireError<String>(DesfireErrorCode.cardConnectionLost, message: error.message, exception: error.exception);
        }
        
        return DesfireError<String>(error.error, message: error.message, exception: error.exception);
      }
      _log("Authentication successful", level: 'INFO');

      // Read encrypted data
      _log("Reading encrypted data", level: 'INFO');
      final readResult = await _readEncryptedData(fileId,
        authResult.data!.sessionKey, fileSettingsResult.data!,
      );
      if (!readResult.isSuccess) {
        _log("[${readResult.errorCode?.code}] ${readResult.errorCode?.description}", level: 'ERROR');
        final error = readResult as DesfireError<String>;
        
        if (error.error == DesfireErrorCode.cardConnectionLost) {
          return DesfireError<String>(DesfireErrorCode.cardConnectionLost, message: error.message, exception: error.exception);
        }
        
        return DesfireError<String>(error.error, message: error.message, exception: error.exception);
      }
      _log("Data read successfully", level: 'INFO');

      return readResult;
      
    } catch (e) {
      _log("Unexpected error: $e", level: 'ERROR');
      return DesfireError<String>(DesfireErrorCode.unknownError, exception: e);
    } finally {
      // Always cleanup NFC session
      _log("Cleaning up NFC session", level: 'INFO');
      try {
        await FlutterNfcKit.finish(iosAlertMessage: "Scan completed");
        _log("NFC session finished successfully", level: 'INFO');
      } catch (e) {
        _log("Error finishing NFC session: $e", level: 'ERROR');
      }
    }
  }
}