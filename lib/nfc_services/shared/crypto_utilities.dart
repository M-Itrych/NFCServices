import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:pointycastle/api.dart';
import 'package:pointycastle/macs/cmac.dart';

/// Custom exception for cryptographic operations
class CryptoException implements Exception {
  final String message;
  const CryptoException(this.message);
  
  @override
  String toString() => 'CryptoException: $message';
}

/// Utility class for cryptographic operations
/// 
/// This class provides methods for AES encryption/decryption, random number generation,
/// byte manipulation, and CMAC calculation for MIFARE Plus operations.
class CryptoUtilities {
  /// AES block size in bytes
  static const int aesBlockSize = 16;
  
  /// Maximum key length in hex characters
  static const int maxKeyLength = 32;
  
  /// Maximum IV length in hex characters
  static const int maxIvLength = 32;

  /// Decrypts AES-CBC encrypted hex data with hex key and IV.
  /// 
  /// [data] the encrypted data in hex format
  /// [key] the AES key in hex format (32 characters)
  /// [iv] the initialization vector in hex format (32 characters)
  /// 
  /// Throws [CryptoException] if decryption fails or parameters are invalid.
  /// Returns the decrypted data as a byte array.
  /// 
  /// This method uses AES-CBC mode with no padding for NFC card operations.
  /// All parameters must be valid hex strings with proper lengths.
  static Uint8List aesDecrypt(String data, String key, String iv) {
    try {
      _validateAesParameters(data, key, iv);
      
      final dataBytes = Uint8List.fromList(hex.decode(data));
      final keyBytes = Uint8List.fromList(hex.decode(key));
      final ivBytes = Uint8List.fromList(hex.decode(iv));
      
      final encryptKey = encrypt.Key(keyBytes);
      final encryptIv = encrypt.IV(ivBytes);
      final encrypter = encrypt.Encrypter(
        encrypt.AES(encryptKey, mode: encrypt.AESMode.cbc, padding: null),
      );
      
      final decrypted = encrypter.decryptBytes(encrypt.Encrypted(dataBytes), iv: encryptIv);
      return Uint8List.fromList(decrypted);
    } catch (e) {
      throw CryptoException('AES decryption failed: $e');
    }
  }

  /// Encrypts data (hex) with AES-CBC using hex key and IV.
  /// 
  /// [data] the data to encrypt in hex format
  /// [key] the AES key in hex format (32 characters)
  /// [iv] the initialization vector in hex format (32 characters)
  /// 
  /// Throws [CryptoException] if encryption fails or parameters are invalid.
  /// Returns the encrypted data as a byte array.
  /// 
  /// This method uses AES-CBC mode with no padding for NFC card operations.
  /// All parameters must be valid hex strings with proper lengths.
  static Uint8List aesEncrypt(String data, String key, String iv) {
    try {
      _validateAesParameters(data, key, iv);
      
      final dataBytes = Uint8List.fromList(hex.decode(data));
      final keyBytes = Uint8List.fromList(hex.decode(key));
      final ivBytes = Uint8List.fromList(hex.decode(iv));
      
      final encryptKey = encrypt.Key(keyBytes);
      final encryptIv = encrypt.IV(ivBytes);
      final encrypter = encrypt.Encrypter(
        encrypt.AES(encryptKey, mode: encrypt.AESMode.cbc, padding: null),
      );
      
      final encrypted = encrypter.encryptBytes(dataBytes, iv: encryptIv);
      return Uint8List.fromList(encrypted.bytes);
    } catch (e) {
      throw CryptoException('AES encryption failed: $e');
    }
  }

  /// Generates a cryptographically secure random byte array.
  /// 
  /// [size] the number of bytes to generate
  /// 
  /// Throws [ArgumentError] if size is not positive.
  /// Returns a secure random byte array.
  /// 
  /// This method uses Random.secure() for cryptographic operations like authentication.
  /// Typically used for generating RandomA and RandomB values in NFC protocols.
  static Uint8List generateSecureRandom(int size) {
    if (size <= 0) {
      throw ArgumentError('Size must be positive, got: $size');
    }
    
    final secureRandom = Random.secure();
    return Uint8List.fromList(List.generate(size, (_) => secureRandom.nextInt(256)));
  }

  /// Rotates a byte array one position to the left.
  /// 
  /// [data] the byte array to rotate
  /// 
  /// Throws [ArgumentError] if data is empty.
  /// Returns the rotated byte array.
  /// 
  /// This operation is commonly used in NFC authentication protocols.
  /// Example: [1,2,3,4] becomes [2,3,4,1]
  static Uint8List rotateLeft(Uint8List data) {
    if (data.isEmpty) {
      throw ArgumentError('Data cannot be empty');
    }
    
    return Uint8List.fromList([...data.sublist(1), data[0]]);
  }

  /// Rotates a byte array one position to the right.
  /// 
  /// [data] the byte array to rotate
  /// 
  /// Throws [ArgumentError] if data is empty.
  /// Returns the rotated byte array.
  /// 
  /// This operation is commonly used in NFC authentication protocols.
  /// Example: [1,2,3,4] becomes [4,1,2,3]
  static Uint8List rotateRight(Uint8List data) {
    if (data.isEmpty) {
      throw ArgumentError('Data cannot be empty');
    }
    
    return Uint8List.fromList([data.last, ...data.sublist(0, data.length - 1)]);
  }

  /// Converts an integer to a 4-character (2-byte) little-endian hex string.
  /// 
  /// [value] the integer to convert
  /// 
  /// Throws [ArgumentError] if value is not between 0 and 65535.
  /// Returns the little-endian hex string.
  /// 
  /// This method is used for NFC command formatting where little-endian byte order is required.
  /// Example: intToLittleEndianHex(258) returns "0201" (not "0102")
  static String intToLittleEndianHex(int value) {
    if (value < 0 || value > 0xFFFF) {
      throw ArgumentError('Value must be between 0 and 65535, got: $value');
    }
    
    final hexString = value.toRadixString(16).padLeft(4, '0');
    return hexString.substring(2, 4) + hexString.substring(0, 2);
  }

  /// Converts a little-endian hex string to an integer.
  /// 
  /// [hexString] the little-endian hex string (4 characters)
  /// 
  /// Throws [ArgumentError] if hexString is not exactly 4 characters or contains invalid hex.
  /// Returns the integer value.
  /// 
  /// This method is used for parsing NFC responses where little-endian byte order is used.
  /// Example: littleEndianHexToInt("0201") returns 258
  static int littleEndianHexToInt(String hexString) {
    if (hexString.length != 4) {
      throw ArgumentError('Hex string must be exactly 4 characters, got: ${hexString.length}');
    }
    
    if (!RegExp(r'^[0-9A-Fa-f]{4}$').hasMatch(hexString)) {
      throw ArgumentError('Invalid hex string: $hexString');
    }
    
    // Swap bytes to convert from little-endian to big-endian
    final bigEndianHex = hexString.substring(2, 4) + hexString.substring(0, 2);
    return int.parse(bigEndianHex, radix: 16);
  }

  /// Computes AES-CMAC with specified output size.
  /// 
  /// [hexKey] the key in hex format (32 characters)
  /// [hexData] the data to compute CMAC for in hex format
  /// [outputBits] the output size in bits (128, 192, or 256)
  /// 
  /// Throws [CryptoException] if CMAC computation fails or parameters are invalid.
  /// Returns the CMAC as an uppercase hex string.
  /// 
  /// This method is used for message authentication in MIFARE Plus operations.
  /// CMAC provides integrity and authenticity verification for NFC commands.
  static String computeAesCmac(String hexKey, String hexData, int outputBits) {
    try {
      _validateCmacParameters(hexKey, hexData, outputBits);
      
      final keyBytes = Uint8List.fromList(hex.decode(hexKey));
      final dataBytes = Uint8List.fromList(hex.decode(hexData));
      
      final cmac = CMac(BlockCipher('AES'), outputBits);
      final keyParam = KeyParameter(keyBytes);
      
      cmac.init(keyParam);
      cmac.update(dataBytes, 0, dataBytes.length);
      
      final macBytes = Uint8List(cmac.macSize);
      cmac.doFinal(macBytes, 0);
      
      return hex.encode(macBytes).toUpperCase();
    } catch (e) {
      throw CryptoException('AES-CMAC-$outputBits computation failed: $e');
    }
  }

  /// XORs two byte arrays of equal length.
  /// 
  /// [data1] the first byte array
  /// [data2] the second byte array
  /// 
  /// Throws [ArgumentError] if arrays have different lengths.
  /// Returns the XOR result as a byte array.
  /// 
  /// This operation is used in cryptographic algorithms and session key generation.
  /// Example: xorBytes([1,2,3], [4,5,6]) returns [5,7,5]
  static Uint8List xorBytes(Uint8List data1, Uint8List data2) {
    if (data1.length != data2.length) {
      throw ArgumentError('Byte arrays must have equal length: ${data1.length} != ${data2.length}');
    }
    
    return Uint8List.fromList(
      List.generate(data1.length, (i) => data1[i] ^ data2[i])
    );
  }

  /// Pads data to a multiple of the specified block size.
  /// 
  /// [data] the data to pad
  /// [blockSize] the block size in bytes
  /// 
  /// Throws [ArgumentError] if blockSize is not positive.
  /// Returns the padded data as a byte array.
  /// 
  /// This method uses PKCS#7 padding for cryptographic operations.
  /// If data is already a multiple of blockSize, no padding is added.
  static Uint8List padToBlockSize(Uint8List data, int blockSize) {
    if (blockSize <= 0) {
      throw ArgumentError('Block size must be positive, got: $blockSize');
    }
    
    final paddingLength = blockSize - (data.length % blockSize);
    if (paddingLength == blockSize) return data;
    
    final paddedData = Uint8List(data.length + paddingLength);
    paddedData.setRange(0, data.length, data);
    
    // PKCS#7 padding
    for (int i = data.length; i < paddedData.length; i++) {
      paddedData[i] = paddingLength;
    }
    
    return paddedData;
  }

  /// Removes PKCS#7 padding from data.
  /// 
  /// [data] the padded data
  /// 
  /// Throws [CryptoException] if padding is invalid or data is empty.
  /// Returns the unpadded data as a byte array.
  /// 
  /// This method validates and removes PKCS#7 padding from decrypted data.
  /// It verifies that the padding length is valid and all padding bytes are correct.
  static Uint8List removePadding(Uint8List data) {
    if (data.isEmpty) {
      throw CryptoException('Cannot remove padding from empty data');
    }
    
    final paddingLength = data.last;
    if (paddingLength <= 0 || paddingLength > data.length) {
      throw CryptoException('Invalid padding length: $paddingLength');
    }
    
    // Verify padding
    for (int i = data.length - paddingLength; i < data.length; i++) {
      if (data[i] != paddingLength) {
        throw CryptoException('Invalid padding');
      }
    }
    
    return data.sublist(0, data.length - paddingLength);
  }

  /// Validates AES encryption/decryption parameters.
  /// 
  /// [data] the data in hex format
  /// [key] the key in hex format
  /// [iv] the IV in hex format
  /// 
  /// Throws [CryptoException] if validation fails (empty data, odd length, invalid hex, wrong lengths).
  /// 
  /// This method ensures all AES operations receive valid parameters before processing.
  static void _validateAesParameters(String data, String key, String iv) {
    if (data.isEmpty) {
      throw CryptoException('Data cannot be empty');
    }
    
    if (data.length % 2 != 0) {
      throw CryptoException('Data must have even length (got ${data.length})');
    }
    
    if (key.length != maxKeyLength) {
      throw CryptoException('Key must be $maxKeyLength hex characters (got ${key.length})');
    }
    
    if (iv.length != maxIvLength) {
      throw CryptoException('IV must be $maxIvLength hex characters (got ${iv.length})');
    }
    
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(data)) {
      throw CryptoException('Data contains invalid hex characters');
    }
    
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(key)) {
      throw CryptoException('Key contains invalid hex characters');
    }
    
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(iv)) {
      throw CryptoException('IV contains invalid hex characters');
    }
  }

  /// Validates CMAC computation parameters.
  /// 
  /// [hexKey] the key in hex format
  /// [hexData] the data in hex format
  /// [outputBits] the output size in bits
  /// 
  /// Throws [CryptoException] if validation fails (invalid key length, empty data, odd length, invalid output bits, invalid hex).
  /// 
  /// This method ensures all CMAC operations receive valid parameters before processing.
  static void _validateCmacParameters(String hexKey, String hexData, int outputBits) {
    if (hexKey.length != maxKeyLength) {
      throw CryptoException('Key must be $maxKeyLength hex characters (got ${hexKey.length})');
    }
    
    if (hexData.isEmpty) {
      throw CryptoException('Data cannot be empty');
    }
    
    if (hexData.length % 2 != 0) {
      throw CryptoException('Data must have even length (got ${hexData.length})');
    }
    
    if (![128, 192, 256].contains(outputBits)) {
      throw CryptoException('Output bits must be 128, 192, or 256 (got $outputBits)');
    }
    
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(hexKey)) {
      throw CryptoException('Key contains invalid hex characters');
    }
    
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(hexData)) {
      throw CryptoException('Data contains invalid hex characters');
    }
  }
}