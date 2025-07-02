import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';

import 'shared/crypto_utilities.dart';
import 'shared/nfc_utilities.dart';

/// Constants for MIFARE Plus operations
class PlusConstants {
  static const int minSector = 1;
  static const int maxSector = 39;
  static const int minBlock = 0;
  static const int maxBlock = 14;
  static const int aesBlockSize = 16;
  static const int keyHexLength = 32;
  static const String successCode = "00";
  static const String nfcSuccessCode = "90";
  static const int maxRetryAttempts = 1;
  static const int transactionIdLength = 4;
  static const int randomDataLength = 16;
}

/// Enum for MIFARE Plus key types
enum KeyType { keyA, keyB }

/// Error codes for MIFARE Plus operations
enum PlusErrorCode {
  success("00", "Success"),
  invalidSector("PPS", "Invalid sector number (must be 1-39)"),
  invalidBlock("PPB", "Invalid block number (must be 0-14)"),
  invalidKeyType("PPKT", "Invalid key type"),
  invalidKeyHex("PPK", "Invalid AES key hex format (must be 32 hex characters)"),
  timeoutError("PPT", "Operation timed out"),
  nfcUnavailable("PPN", "NFC is not available"),
  sessionError("PPSN", "NFC session error"),
  unexpectedState("PPU", "Unexpected application state"),
  userCancelled("PPUC", "User cancelled operation"),
  cardError("CARD", "Card error"),
  authenticationFailed("PPAF", "Authentication failed"),
  sessionKeyError("PPSE", "Session key generation failed"),
  cmacError("PPCM", "CMAC calculation failed"),
  dataDecryptionError("PPDD", "Data decryption failed"),
  invalidResponse("PPIR", "Invalid card response"),
  cardConnectionLost("PCCL", "Card connection lost - please keep card steady"),
  communicationError("PCE", "Communication error with card"),
  unknownError("UE", "Unknown error. Try again");

  const PlusErrorCode(this.code, this.description);
  final String code;
  final String description;
  @override
  String toString() => code;
}

/// Maps NFC error codes to descriptive messages
const Map<String, String> nfcErrorCodeMap = {
  "06": "Authentication Error",
  "07": "Command Overflow",
  "08": "Invalid MAC",
  "09": "Invalid Block Number",
  "0A": "Not Existing Block Number",
  "0B": "Conditions of use not satisfied",
  "0C": "Length Error",
  "0F": "General Manipulation Error",
  "90": "Success Code",
};

/// Sealed class for consistent result handling
sealed class PlusResult<T> {
  const PlusResult();
  
  bool get isError => this is PlusError<T>;
  bool get isSuccess => this is PlusSuccess<T>;
  PlusErrorCode? get errorCode => this is PlusError<T> ? (this as PlusError<T>).error : null;
  T? get data => this is PlusSuccess<T> ? (this as PlusSuccess<T>).data : null;
}

class PlusError<T> extends PlusResult<T> {
  /// Creates a PlusError with an optional message and exception for debugging.
  const PlusError(this.error, {this.message, this.exception});
  final PlusErrorCode error;
  final String? message;
  final Object? exception;
  @override
  String toString() => 'PlusError(${error.description}${message != null ? ': $message' : ''}${exception != null ? ' Exception: $exception' : ''})';
}

class PlusSuccess<T> extends PlusResult<T> {
  const PlusSuccess(this.data);
  final T data;
  @override
  String toString() => 'PlusSuccess($data)';
}

/// Result of MIFARE Plus authentication operation
class PlusAuthResult {
  const PlusAuthResult({
    required this.code,
    required this.plaRNDB,
    required this.plaRNDA,
    required this.transactionID,
    this.description = "",
  });

  final String code;  
  final String plaRNDB;
  final String plaRNDA;
  final String transactionID;
  final String description;
}

/// Session keys generated after successful authentication
class PlusSessionKeys {
  const PlusSessionKeys({
    required this.kenc,
    required this.kmac,
  });

  final String kenc;
  final String kmac;
}

/// Result of block read operation
class PlusReadResult {
  const PlusReadResult({
    required this.code,
    required this.data,
    this.description = "",
    this.cardCode = "",
  });

  final String code;
  final String data;
  final String description;
  final String cardCode;
}

/// Main MIFARE Plus service for authentication and block reading
class PlusServices {
  final bool debugMode;
  final int timeout;
  final String alertMessage;
  final String multipleTagMessage;

  /// Creates a new PlusServices instance
  /// 
  /// [debugMode] enables detailed logging of operations
  /// [timeout] specifies the NFC operation timeout in seconds
  /// [alertMessage] message shown to user during NFC scanning
  /// [multipleTagMessage] message shown when multiple tags are detected
  PlusServices({
    this.debugMode = false,
    this.timeout = 10,
    this.alertMessage = "Scan your MIFARE Plus card",
    this.multipleTagMessage = "Multiple tags found!"
  });

  /// Prints debug messages with log level if debugMode is true
  void _log(String message, {String level = 'INFO'}) {
    if (debugMode) {
      print('[${DateTime.now().toIso8601String()}][$level] $message');
    }
  }

  /// Validates input parameters for MIFARE Plus operations
  /// 
  /// Returns [PlusErrorCode.success] if validation passes, otherwise returns
  /// the appropriate error code with description.
  PlusErrorCode _validatePlusReadParameters(
    int sector,
    int block,
    KeyType keyType,
    String keyHex,
  ) {
    ArgumentError.checkNotNull(sector, 'sector');
    ArgumentError.checkNotNull(block, 'block');
    ArgumentError.checkNotNull(keyType, 'keyType');
    ArgumentError.checkNotNull(keyHex, 'keyHex');

    if (sector < PlusConstants.minSector || sector > PlusConstants.maxSector) {
      return PlusErrorCode.invalidSector;
    }
    if (block < PlusConstants.minBlock || block > PlusConstants.maxBlock) {
      return PlusErrorCode.invalidBlock;
    }
    if (keyHex.length != PlusConstants.keyHexLength) {
      return PlusErrorCode.invalidKeyHex;
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(keyHex)) {
      return PlusErrorCode.invalidKeyHex;
    }
    return PlusErrorCode.success;
  }

  /// Converts KeyType enum to int for legacy compatibility
  int _keyTypeToInt(KeyType keyType) => keyType == KeyType.keyA ? 0 : 1;

  /// Generates MIFARE Plus authentication command
  /// 
  /// [sector] the sector number (1-39)
  /// [keyType] the key type (0 for KeyA, 1 for KeyB)
  /// 
  /// Returns the authentication command string in hex format.
  /// 
  /// This method constructs the first authentication command (70h) for MIFARE Plus.
  /// The command format is: 70 + keySectorNumber + 4000
  /// where keySectorNumber = sector * 2 + keyType
  String _generateAuthCommand(int sector, int keyType) {
    final keySectorNumber = (sector * 2 + keyType).toRadixString(16).padLeft(2, '0').toUpperCase();
    _log("Generated authentication command: 70${keySectorNumber}4000", level: 'INFO');
    return "70${keySectorNumber}4000";
  }

  /// Helper to get NFC error message from code
  /// 
  /// [code] the NFC error code (2-character hex string)
  /// 
  /// Returns a human-readable error message for the given error code.
  /// 
  /// This method maps MIFARE Plus error codes to descriptive messages
  /// for better error reporting and debugging.
  String _getNfcErrorMessage(String code) {
    return nfcErrorCodeMap[code] ?? "Unknown error code: $code";
  }



  /// Processes the first authentication step
  /// 
  /// [sector] the sector number (1-39)
  /// [keyType] the key type (0 for KeyA, 1 for KeyB)
  /// [keyHex] the AES key in hex format (32 characters)
  /// 
  /// Returns authentication result with decrypted RandomB or error.
  /// 
  /// This method sends the first authentication command (70h) to the card,
  /// receives the encrypted RandomB, and decrypts it using the provided key.
  /// It handles various error conditions and connection issues.
  Future<PlusResult<Uint8List>> _processFirstAuthStep(int sector, int keyType, String keyHex) async {
    try {
      final authCmd = _generateAuthCommand(sector, keyType);
      _log("Sending authentication command: $authCmd", level: 'INFO');
      
      final response = await sendCommand(authCmd);
      _log("Authentication response: $response", level: 'INFO');
      
      if (!response.startsWith(PlusConstants.nfcSuccessCode)) {
        final errorCode = response.substring(0, 2);
        final errorMsg = _getNfcErrorMessage(errorCode);
        _log("Authentication failed: [$errorCode] $errorMsg", level: 'WARNING');
        return PlusError<Uint8List>(PlusErrorCode.cardError, message: "[$errorCode] $errorMsg");
      }

      final encRNDB = response.substring(2);
      _log("Encrypted RandomB: $encRNDB", level: 'INFO');
      
      try {
        final plaRNDB = CryptoUtilities.aesDecrypt(encRNDB, keyHex, "00000000000000000000000000000000");
        _log("Decrypted RandomB: ${hex.encode(plaRNDB)}", level: 'INFO');
        return PlusSuccess(plaRNDB);
      } catch (e) {
        _log("Failed to decrypt RandomB: $e", level: 'ERROR');
        return PlusError<Uint8List>(PlusErrorCode.authenticationFailed, exception: e);
      }
    } catch (e) {
      final errorMessage = e.toString().toLowerCase();
      if (errorMessage.contains('tag was lost') || 
          errorMessage.contains('connection') ||
          errorMessage.contains('communication error')) {
        _log("Card connection lost during first auth step: $e", level: 'ERROR');
        return PlusError<Uint8List>(PlusErrorCode.cardConnectionLost, message: "Card connection lost - please keep card steady", exception: e);
      }
      _log("Communication error during first auth step: $e", level: 'ERROR');
      return PlusError<Uint8List>(PlusErrorCode.communicationError, message: "Communication error with card", exception: e);
    }
  }

  /// Processes the second authentication step
  /// 
  /// [plaRNDB] the decrypted RandomB from first authentication step
  /// [plaRNDA] the generated RandomA for this authentication
  /// [keyHex] the AES key in hex format (32 characters)
  /// [attempt] current retry attempt number
  /// 
  /// Returns authentication result with transaction ID and session data or error.
  /// 
  /// This method sends the second authentication command (72h) to the card,
  /// which includes the encrypted RandomA + rotated RandomB. It validates
  /// the card's response and extracts the transaction ID for subsequent operations.
  Future<PlusResult<PlusAuthResult>> _processSecondAuthStep(
    Uint8List plaRNDB, 
    Uint8List plaRNDA, 
    String keyHex, 
    int attempt
  ) async {
    final rplaRNDB = CryptoUtilities.rotateLeft(plaRNDB);
    _log("Rotated RandomB: ${hex.encode(rplaRNDB)}", level: 'INFO');
    
    final plaRNDArB = Uint8List.fromList([...plaRNDA, ...rplaRNDB]);
    _log("Combined RandomA + Rotated RandomB: ${hex.encode(plaRNDArB)}", level: 'INFO');
    
    try {
      final encRNDArB = CryptoUtilities.aesEncrypt(hex.encode(plaRNDArB), keyHex, "00000000000000000000000000000000");
      _log("Encrypted RandomA + Rotated RandomB: ${hex.encode(encRNDArB)}", level: 'INFO');

      final authCmd2 = "72${hex.encode(encRNDArB)}";
      _log("Sending second authentication command: $authCmd2", level: 'INFO');
      
      final response2 = await sendCommand(authCmd2);
      _log("Second authentication response: $response2", level: 'INFO');
      
      // Check for error response
      if (!response2.startsWith(PlusConstants.nfcSuccessCode)) {
        final errorCode = response2.substring(0, 2);
        final errorMsg = _getNfcErrorMessage(errorCode);
        _log("Authentication failed: [$errorCode] $errorMsg", level: 'WARNING');
        
        // Retry once if this is the first attempt
        if (attempt < PlusConstants.maxRetryAttempts) {
          _log("Retrying authentication (attempt ${attempt + 1})", level: 'INFO');
          return PlusError<PlusAuthResult>(PlusErrorCode.authenticationFailed, message: "[$errorCode] $errorMsg");
        }
        
        return PlusError<PlusAuthResult>(PlusErrorCode.cardError, message: "[$errorCode] $errorMsg");
      }
      
      // Process successful response
      return _validateAuthResult(response2, keyHex, plaRNDA, plaRNDB);
    } catch (e) {
      final errorMessage = e.toString().toLowerCase();
      if (errorMessage.contains('tag was lost') || 
          errorMessage.contains('connection') ||
          errorMessage.contains('communication error')) {
        _log("Card connection lost during second auth step: $e", level: 'ERROR');
        return PlusError<PlusAuthResult>(PlusErrorCode.cardConnectionLost, message: "Card connection lost - please keep card steady", exception: e);
      }
      _log("Communication error during second auth step: $e", level: 'ERROR');
      return PlusError<PlusAuthResult>(PlusErrorCode.communicationError, message: "Communication error with card", exception: e);
    }
  }

  /// Validates authentication result and extracts transaction ID
  /// 
  /// [response2] the card response from second authentication step
  /// [keyHex] the AES key in hex format (32 characters)
  /// [plaRNDA] the generated RandomA for this authentication
  /// [plaRNDB] the decrypted RandomB from first authentication step
  /// 
  /// Returns authentication result with transaction ID or validation error.
  /// 
  /// This method decrypts the card's response, validates the RandomA rotation,
  /// and extracts the transaction ID. It ensures the authentication was successful
  /// before proceeding with subsequent operations.
  PlusResult<PlusAuthResult> _validateAuthResult(
    String response2, 
    String keyHex, 
    Uint8List plaRNDA, 
    Uint8List plaRNDB
  ) {
    final encData = response2.substring(2);
    _log("Encrypted authentication data: $encData", level: 'INFO');
    
    try {
      final plaData = CryptoUtilities.aesDecrypt(encData, keyHex, "00000000000000000000000000000000");
      _log("Decrypted authentication data: ${hex.encode(plaData)}", level: 'INFO');
      
      if (plaData.length < 20) {
        _log("Invalid authentication data length: ${plaData.length}", level: 'ERROR');
        return PlusError<PlusAuthResult>(PlusErrorCode.invalidResponse);
      }
      
      final plaRNDAres = plaData.sublist(4, 20);
      final rotatedRNDA = CryptoUtilities.rotateLeft(plaRNDA);
      final authOnRNDA = hex.encode(plaRNDAres) == hex.encode(rotatedRNDA);
      
      if (!authOnRNDA) {
        _log("Authentication failed: plaRNDAres != rotated RNDA", level: 'WARNING');
        _log("Expected: ${hex.encode(rotatedRNDA)}, Got: ${hex.encode(plaRNDAres)}", level: 'WARNING');
        return PlusError<PlusAuthResult>(PlusErrorCode.authenticationFailed);
      }
      
      _log("Authentication on RNDA: $authOnRNDA", level: 'INFO');
      
      final transactionID = plaData.sublist(0, PlusConstants.transactionIdLength);
      _log("Transaction ID: ${hex.encode(transactionID)}", level: 'INFO');
      
      final authResult = PlusAuthResult(
        code: PlusConstants.successCode,
        plaRNDB: hex.encode(plaRNDB),
        plaRNDA: hex.encode(plaRNDA),
        transactionID: hex.encode(transactionID),
      );

      _log("Authentication successful", level: 'INFO');
      return PlusSuccess(authResult);
    } catch (e) {
      _log("Failed to validate authentication result: $e", level: 'ERROR');
      return PlusError<PlusAuthResult>(PlusErrorCode.authenticationFailed, exception: e);
    }
  }

  /// Authenticates with MIFARE Plus sector
  /// 
  /// [sector] the sector number to authenticate with
  /// [keyType] the key type (0 for KeyA, 1 for KeyB)
  /// [keyHex] the AES key in hex format
  /// [attempt] current retry attempt (0-based)
  /// 
  /// Returns authentication result with session data or error.
  /// 
  /// This method orchestrates the complete MIFARE Plus authentication process,
  /// including both authentication steps and retry logic. It generates RandomA,
  /// processes both authentication phases, and returns the complete authentication result.
  Future<PlusResult<PlusAuthResult>> _authenticateSector(
    int sector, 
    int keyType, 
    String keyHex, {
    int attempt = 0,
  }) async {
    try {
      _log("Starting MIFARE Plus authentication for sector $sector, key type $keyType", level: 'INFO');
      
      // Step 1: First authentication step
      final firstStepResult = await _processFirstAuthStep(sector, keyType, keyHex);
      if (firstStepResult.isError) {
        return PlusError<PlusAuthResult>(firstStepResult.errorCode!, message: (firstStepResult as PlusError<Uint8List>).message, exception: (firstStepResult as PlusError<Uint8List>).exception);
      }
      
      final plaRNDB = firstStepResult.data!;
      
      // Step 2: Generate RandomA
      final plaRNDA = CryptoUtilities.generateSecureRandom(PlusConstants.randomDataLength);
      _log("Generated RandomA: ${hex.encode(plaRNDA)}", level: 'INFO');
      
      // Step 3: Second authentication step
      final secondStepResult = await _processSecondAuthStep(plaRNDB, plaRNDA, keyHex, attempt);
      if (secondStepResult.isError) {
        // Retry logic
        if (attempt < PlusConstants.maxRetryAttempts) {
          _log("Retrying authentication (attempt ${attempt + 1})", level: 'INFO');
          return await _authenticateSector(sector, keyType, keyHex, attempt: attempt + 1);
        }
        return secondStepResult;
      }
      
      // Authentication completed successfully
      return secondStepResult;
      
    } catch (e) {
      _log("Authentication error: $e", level: 'ERROR');
      return PlusError<PlusAuthResult>(PlusErrorCode.authenticationFailed, exception: e);
    }
  }

  /// Generates session keys from authentication data
  /// 
  /// [plaRNDB] the decrypted RandomB from authentication
  /// [plaRNDA] the generated RandomA from authentication
  /// 
  /// Returns session keys for encryption and MAC operations or error.
  /// 
  /// This method generates the encryption key (Kenc) and MAC key (Kmac) from
  /// the authentication random values using the MIFARE Plus key derivation algorithm.
  /// The keys are used for subsequent encrypted communications with the card.
  PlusResult<PlusSessionKeys> _generateSessionKeys(String plaRNDB, String plaRNDA) {
    try {
      _log("Generating session keys from RandomA: $plaRNDA, RandomB: $plaRNDB", level: 'INFO');
      
      // Convert hex strings to byte arrays
      final plaRNDABytes = hex.decode(plaRNDA);
      final plaRNDBBytes = hex.decode(plaRNDB);
      
      if (plaRNDABytes.length != PlusConstants.randomDataLength || plaRNDBBytes.length != PlusConstants.randomDataLength) {
        _log("Invalid random data length", level: 'ERROR');
        return PlusError<PlusSessionKeys>(PlusErrorCode.sessionKeyError);
      }
      
      // Generate encryption key
      final encKeyPA = plaRNDABytes.sublist(11, 16);
      final encKeyPB = plaRNDBBytes.sublist(11, 16);
      final encKeyPC = plaRNDABytes.sublist(4, 9);
      final encKeyPD = plaRNDBBytes.sublist(4, 9);
      final encKeyPE = Uint8List.fromList(List.generate(5, (i) => encKeyPC[i] ^ encKeyPD[i]));
      final encKey = Uint8List.fromList([...encKeyPA, ...encKeyPB, ...encKeyPE, 0x11]);
      
      _log("Encryption key parts - PA: ${hex.encode(encKeyPA)}, PB: ${hex.encode(encKeyPB)}, PC: ${hex.encode(encKeyPC)}, PD: ${hex.encode(encKeyPD)}, PE: ${hex.encode(encKeyPE)}", level: 'INFO');
      _log("Final encryption key: ${hex.encode(encKey)}", level: 'INFO');
      
      // Generate MAC key
      final macKeyPA = plaRNDABytes.sublist(7, 12);
      final macKeyPB = plaRNDBBytes.sublist(7, 12);
      final macKeyPC = plaRNDABytes.sublist(0, 5);
      final macKeyPD = plaRNDBBytes.sublist(0, 5);
      final macKeyPE = Uint8List.fromList(List.generate(5, (i) => macKeyPC[i] ^ macKeyPD[i]));
      final macKey = Uint8List.fromList([...macKeyPA, ...macKeyPB, ...macKeyPE, 0x22]);
      
      _log("MAC key parts - PA: ${hex.encode(macKeyPA)}, PB: ${hex.encode(macKeyPB)}, PC: ${hex.encode(macKeyPC)}, PD: ${hex.encode(macKeyPD)}, PE: ${hex.encode(macKeyPE)}", level: 'INFO');
      _log("Final MAC key: ${hex.encode(macKey)}", level: 'INFO');
      
      final sessionKeys = PlusSessionKeys(
        kenc: hex.encode(encKey),
        kmac: hex.encode(macKey),
      );
      
      _log("Session keys generated successfully", level: 'INFO');
      return PlusSuccess(sessionKeys);
    } catch (e) {
      _log("Session key generation error: $e", level: 'ERROR');
      return PlusError<PlusSessionKeys>(PlusErrorCode.sessionKeyError, exception: e);
    }
  }

  /// Generates block read command code based on parameters
  /// 
  /// [isPlaintext] whether to read data in plaintext mode
  /// [requiresMacOnResponse] whether MAC is required on response
  /// 
  /// Returns the command code as a 2-character hex string.
  /// 
  /// This method determines the appropriate command code for block reading:
  /// - 31h: Encrypted data with MAC on response
  /// - 32h: Plaintext data without MAC on response
  /// - 33h: Plaintext data with MAC on response
  String _generateBlockReadCommandCode(bool isPlaintext, bool requiresMacOnResponse) {
    final commandCode = isPlaintext 
        ? (requiresMacOnResponse ? "33" : "32")
        : "31";
    _log("Generated command code: $commandCode (Plaintext: $isPlaintext, MAC on response: $requiresMacOnResponse)", level: 'INFO');
    return commandCode;
  }

  /// Generates complete block read command
  /// 
  /// [commandCode] the command code (31h, 32h, or 33h)
  /// [sector] the sector number (1-39)
  /// [cMAC] the calculated CMAC for command authentication
  /// 
  /// Returns the complete block read command in hex format.
  /// 
  /// This method constructs the final block read command with the format:
  /// commandCode + sectorAddressLittleEndian + 03 + cMAC
  /// where sectorAddressLittleEndian = (sector * 4) in little-endian format
  String _generateBlockReadCommand(String commandCode, int sector, String cMAC) {
    final littleEndianSector = CryptoUtilities.intToLittleEndianHex(sector * 4);
    final command = "$commandCode${littleEndianSector}03$cMAC";
    _log("Generated block read command: $command (Sector: $sector, Little-endian sector: $littleEndianSector, CMAC: $cMAC)", level: 'INFO');
    return command;
  }

  /// Calculates CMAC for command authentication
  /// 
  /// [kmac] the MAC key in hex format
  /// [transactionID] the transaction ID from authentication
  /// [sector] the sector number (1-39)
  /// [command] the command code (31h, 32h, or 33h)
  /// [authKey] the authentication key in hex format
  /// 
  /// Returns the calculated CMAC as a hex string.
  /// 
  /// This method calculates the CMAC for command authentication using the MIFARE Plus
  /// algorithm. It encrypts the MAC key with the authentication key, then computes
  /// the CMAC over the command data including transaction ID and sector address.
  String _calculateCmac(String kmac, String transactionID, int sector, String command, String authKey) {
    try {
      final sectorAddressLittleEndian = CryptoUtilities.intToLittleEndianHex(sector * 4);
      final commandForMac = "${command}0000$transactionID${sectorAddressLittleEndian}03";
      _log("Command for MAC calculation: $commandForMac", level: 'INFO');
      _log("Raw MAC key: $kmac", level: 'INFO');
      _log("Transaction ID: $transactionID", level: 'INFO');
      _log("Sector address (little-endian): $sectorAddressLittleEndian", level: 'INFO');
      
      // Encrypt the MAC key with the authentication key before using it for CMAC
      final encryptedMacKey = CryptoUtilities.aesEncrypt(kmac, authKey, "00000000000000000000000000000000");
      _log("Encrypted MAC key: ${hex.encode(encryptedMacKey)}", level: 'INFO');
      
      final macOnCommand = CryptoUtilities.computeAesCmac(hex.encode(encryptedMacKey), commandForMac, 128);
      _log("Full CMAC result: $macOnCommand", level: 'INFO');
      
      final regExp = RegExp(r'(?:..)(..)');
      final matches = regExp.allMatches(macOnCommand);
      final cmac = matches.map((m) => m.group(1)!).join();
      _log("Extracted CMAC: $cmac", level: 'INFO');
      
      return cmac;
    } catch (e) {
      _log("CMAC calculation failed: $e", level: 'ERROR');
      throw CryptoException('CMAC calculation failed: $e');
    }
  }

  /// Reads block data from MIFARE Plus card
  /// 
  /// [sector] the sector number (1-39)
  /// [kenc] the encryption key in hex format
  /// [kmac] the MAC key in hex format
  /// [transactionID] the transaction ID from authentication
  /// [isPlaintext] whether to read data in plaintext mode
  /// [requiresMacOnResponse] whether MAC is required on response
  /// [authKey] the authentication key in hex format
  /// 
  /// Returns block read result with data or error.
  /// 
  /// This method performs the actual block read operation on the MIFARE Plus card.
  /// It generates the appropriate command, calculates CMAC, sends the command,
  /// and processes the response based on the specified communication mode.
  Future<PlusResult<PlusReadResult>> _readBlockData(
    int sector,
    String kenc,
    String kmac,
    String transactionID,
    bool isPlaintext,
    bool requiresMacOnResponse,
    String authKey,
  ) async {
    try {
      _log("Starting block read operation", level: 'INFO');
      _log("Parameters - Sector: $sector, Plaintext: $isPlaintext, MAC on response: $requiresMacOnResponse", level: 'INFO');
      _log("Session keys - Kenc: $kenc, Kmac: $kmac", level: 'INFO');
      _log("Transaction ID: $transactionID", level: 'INFO');
      
      final commandCode = _generateBlockReadCommandCode(isPlaintext, requiresMacOnResponse);
      final cmac = _calculateCmac(kmac, transactionID, sector, commandCode, authKey);
      final readCommand = _generateBlockReadCommand(commandCode, sector, cmac);
      
      _log("Sending block read command: $readCommand", level: 'INFO');
      final response = await sendCommand(readCommand);
      _log("Block read response: $response", level: 'INFO');
      
      if (!response.startsWith(PlusConstants.nfcSuccessCode)) {
        final errorCode = response.substring(0, 2);
        final errorMsg = _getNfcErrorMessage(errorCode);
        _log("Block read failed: [$errorCode] $errorMsg", level: 'WARNING');
        return PlusError<PlusReadResult>(PlusErrorCode.cardError, message: "[$errorCode] $errorMsg");
      }

      final cardCode = response.substring(0, 2);
      final data = response.substring(2);
      _log("Card response code: $cardCode", level: 'INFO');
      _log("Block data: $data", level: 'INFO');

      final readResult = PlusReadResult(
        code: PlusConstants.successCode,
        description: "Block read successful",
        cardCode: cardCode,
        data: data,
      );

      _log("Block read operation completed successfully", level: 'INFO');
      return PlusSuccess(readResult);
    } catch (e) {
      final errorMessage = e.toString().toLowerCase();
      if (errorMessage.contains('tag was lost') || 
          errorMessage.contains('connection') ||
          errorMessage.contains('communication error')) {
        _log("Card connection lost during block read: $e", level: 'ERROR');
        return PlusError<PlusReadResult>(PlusErrorCode.cardConnectionLost, message: "Card connection lost - please keep card steady", exception: e);
      }
      _log("Block read error: $e", level: 'ERROR');
      return PlusError<PlusReadResult>(PlusErrorCode.communicationError, message: "Communication error with card", exception: e);
    }
  }

  /// Decrypts block data using session keys
  /// 
  /// [encryptedData] the encrypted data from the card
  /// [sessionKey] the session encryption key in hex format
  /// [authKey] the authentication key in hex format
  /// [transactionID] the transaction ID from authentication
  /// 
  /// Returns the decrypted data as a hex string.
  /// 
  /// This method decrypts block data that was read in encrypted mode.
  /// It encrypts the session key with the authentication key, then uses
  /// the encrypted session key to decrypt the block data.
  String _decryptBlockData(String encryptedData, String sessionKey, String authKey, String transactionID) {
    try {
      _log("Decrypting encrypted data", level: 'INFO');
      _log("Encrypted data: $encryptedData", level: 'INFO');
      _log("Decryption key: $sessionKey", level: 'INFO');
      
      // Encrypt the session key with the authentication key before using it for decryption
      final encryptedEncryptionKey = CryptoUtilities.aesEncrypt(sessionKey, authKey, "00000000000000000000000000000000");
      final decryptedData = CryptoUtilities.aesDecrypt(
        encryptedData.substring(0, 96),
        hex.encode(encryptedEncryptionKey),
        "010000000100000001000000$transactionID"
      );
      final decryptedHex = hex.encode(decryptedData);
      _log("Decrypted data: $decryptedHex", level: 'INFO');
      return decryptedHex;
    } catch (e) {
      _log("Data decryption failed: $e", level: 'ERROR');
      throw CryptoException('Data decryption failed: $e');
    }
  }

  /// Extracts block data from the full response
  /// 
  /// [data] the full data response from the card
  /// [block] the block number (0-14)
  /// [isPlaintext] whether the data is in plaintext mode
  /// 
  /// Returns the extracted block data as a hex string.
  /// 
  /// This method extracts the specific block data from the full response.
  /// Each block is 32 characters (16 bytes) in the response, and this method
  /// calculates the correct offset based on the block number.
  String _extractBlockData(String data, int block, bool isPlaintext) {
    if (isPlaintext) {
      final blockData = data.substring(32 * block, 32 * (block + 1));
      _log("Returning plaintext data: $blockData", level: 'INFO');
      return blockData;
    } else {
      final blockData = data.substring(32 * block, 32 * (block + 1));
      _log("Block data: $blockData", level: 'INFO');
      return blockData;
    }
  }
  
  /// Main method for MIFARE Plus read operations
  /// 
  /// [sector] the sector number (1-39)
  /// [block] the block number (0-14)
  /// [keyType] the key type (KeyA or KeyB)
  /// [keyHex] the AES key in hex format (32 characters)
  /// [isPlaintext] whether to read in plaintext mode
  /// [requiresMacOnResponse] whether MAC is required on response
  /// 
  /// Returns PlusResult<String> with block data or error
  Future<PlusResult<String>> readPlus(
    int sector,
    int block,
    KeyType keyType,
    String keyHex, {
    bool isPlaintext = true,
    bool requiresMacOnResponse = false,
    }) async {
    try {
      _log("Starting MIFARE Plus read operation", level: 'INFO');
      _log("Input parameters - Sector: $sector, Block: $block, Key type: $keyType", level: 'INFO');
      _log("Communication settings - Plaintext: $isPlaintext, MAC on response: $requiresMacOnResponse", level: 'INFO');
      _log("Authentication key: $keyHex", level: 'INFO');

      // Validate parameters
      final validationResult = _validatePlusReadParameters(sector, block, keyType, keyHex);
      if (validationResult != PlusErrorCode.success) {
        _log("[${validationResult.code}] ${validationResult.description}", level: 'WARNING');
        return PlusError<String>(validationResult, message: validationResult.description);
      }
      _log("Parameter validation passed", level: 'INFO');

      // Check NFC availability
      _log("Checking NFC availability", level: 'INFO');
      final nfcStatus = await isNfcAvailable();
      if (nfcStatus.code.code != NfcErrorCode.success.code) {
        _log("[${nfcStatus.code}] ${nfcStatus.message ?? ''}", level: 'ERROR');
        return PlusError<String>(PlusErrorCode.nfcUnavailable, message: nfcStatus.message);
      }
      _log("NFC is available", level: 'INFO');
      _log("Passed NFC check, about to poll for card", level: 'INFO');

      // Poll for card
      _log("Polling for NFC card", level: 'INFO');
      final cardInfo = await pollForCard(debugMode, timeout, alertMessage, multipleTagMessage);
      if (cardInfo.code.code != NfcErrorCode.success.code) {
        _log("[${cardInfo.code}] ${cardInfo.message ?? ''}", level: 'ERROR');
        return PlusError<String>(PlusErrorCode.sessionError, message: cardInfo.message);
      }
      _log("NFC card detected", level: 'INFO');

      // Authenticate with sector
      _log("Starting sector authentication", level: 'INFO');
      final authResult = await _authenticateSector(sector, _keyTypeToInt(keyType), keyHex);
      if (authResult.isError) {
        _log("[${authResult.errorCode?.code}] ${authResult.errorCode?.description}", level: 'ERROR');
        final error = authResult as PlusError<PlusAuthResult>;
        
        // Special handling for connection lost errors
        if (error.error == PlusErrorCode.cardConnectionLost) {
          return PlusError<String>(PlusErrorCode.cardConnectionLost, message: error.message, exception: error.exception);
        }
        
        return PlusError<String>(error.error, message: error.message, exception: error.exception);
      }
      _log("Sector authentication successful", level: 'INFO');

      // Generate session keys
      _log("Generating session keys", level: 'INFO');
      final sessionKeysResult = _generateSessionKeys(authResult.data!.plaRNDB, authResult.data!.plaRNDA);
      if (sessionKeysResult.isError) {
        _log("Session key generation failed", level: 'ERROR');
        return PlusError<String>(sessionKeysResult.errorCode!, message: sessionKeysResult.errorCode?.description);
      }
      _log("Session keys generated", level: 'INFO');

      // Read block data
      _log("Reading block data", level: 'INFO');
      final readResult = await _readBlockData(
        sector,
        sessionKeysResult.data!.kenc,
        sessionKeysResult.data!.kmac,
        authResult.data!.transactionID,
        isPlaintext,
        requiresMacOnResponse,
        keyHex
      );
      if (readResult.isError) {
        _log("[${readResult.errorCode?.code}] ${readResult.errorCode?.description}", level: 'ERROR');
        final error = readResult as PlusError<PlusReadResult>;
        
        // Special handling for connection lost errors
        if (error.error == PlusErrorCode.cardConnectionLost) {
          return PlusError<String>(PlusErrorCode.cardConnectionLost, message: error.message, exception: error.exception);
        }
        
        return PlusError<String>(error.error, message: error.message, exception: error.exception);
      }
      _log("Block data read successfully", level: 'INFO');

      // Process and return data
      String processedData;
      if (isPlaintext) {
        processedData = readResult.data!.data;
      } else {
        processedData = _decryptBlockData(readResult.data!.data, sessionKeysResult.data!.kenc, keyHex, authResult.data!.transactionID);
      }
      
      final blockData = _extractBlockData(processedData, block, isPlaintext);
      return PlusSuccess(blockData);
      
    } catch (e) {
      _log("Unexpected error: $e", level: 'ERROR');
      return PlusError<String>(PlusErrorCode.unknownError, exception: e);
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