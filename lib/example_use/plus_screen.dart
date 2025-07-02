import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../nfc_services/plus_services.dart';
import '../nfc_services/shared/binary_conversion.dart';

/// Custom text formatter to convert input to uppercase
class UpperCaseTextFormatter extends TextInputFormatter {
  @override
  TextEditingValue formatEditUpdate(
    TextEditingValue oldValue,
    TextEditingValue newValue,
  ) {
    return TextEditingValue(
      text: newValue.text.toUpperCase(),
      selection: newValue.selection,
    );
  }
}

class PlusScreen extends StatefulWidget {
  const PlusScreen({Key? key}) : super(key: key);

  @override
  State<PlusScreen> createState() => _PlusScreenState();
}

class _PlusScreenState extends State<PlusScreen> {
  final _formKey = GlobalKey<FormState>();
  final TextEditingController _sectorController = TextEditingController(text: '4');
  final TextEditingController _blockController = TextEditingController(text: '0');
  final TextEditingController _fbpController = TextEditingController(text: '0');
  final TextEditingController _lbpController = TextEditingController(text: '15');
  final TextEditingController _keyController = TextEditingController(text: '66666666666666666666666666666666');
  final TextEditingController _resultController = TextEditingController();
  final TextEditingController _decodedController = TextEditingController();
  String _selectedKeyType = 'Key B'; // Default selection
  String _selectedFormat = 'HEX'; // Default format selection
  final List<String> _keyTypes = ['Key A', 'Key B'];
  final List<String> _formats = ['HEX', 'BIN', 'ASCII'];
  bool _isScanning = false;
  bool _isDecoding = false;
  
  // MIFARE Plus communication settings (MAC on command is always true)
  String _communicationType = 'Plaintext';
  String _responseType = 'No MAC';
  
  final List<String> _communicationTypes = ['Plaintext', 'Encrypted'];
  final List<String> _responseTypes = ['No MAC', 'MAC on Response'];

  /// Get boolean values from dropdown selections for service calls
  bool get _isPlaintext => _communicationType == 'Plaintext';
  bool get _requiresMacOnResponse => _responseType == 'MAC on Response';

  @override
  void dispose() {
    _sectorController.dispose();
    _blockController.dispose();
    _fbpController.dispose();
    _lbpController.dispose();
    _keyController.dispose();
    _resultController.dispose();
    _decodedController.dispose();
    super.dispose();
  }

  /// Validate sector input (1-39)
  String? _validateSector(String? value) {
    if (value == null || value.isEmpty) {
      return 'Sector is required';
    }
    final sector = int.tryParse(value);
    if (sector == null || sector < 1 || sector > 39) {
      return 'Sector must be between 1-39';
    }
    return null;
  }

  /// Validate block input (0-14)
  String? _validateBlock(String? value) {
    if (value == null || value.isEmpty) {
      return 'Block is required';
    }
    final block = int.tryParse(value);
    if (block == null || block < 0 || block > 14) {
      return 'Block must be between 0-14';
    }
    return null;
  }

  /// Validate byte position input (0-15)
  String? _validateBytePosition(String? value, String fieldName) {
    if (value == null || value.isEmpty) {
      return '$fieldName is required';
    }
    final position = int.tryParse(value);
    if (position == null || position < 0 || position > 15) {
      return '$fieldName must be between 0-15';
    }
    return null;
  }

  /// Validate authentication key (32 hex characters)
  String? _validateAuthKey(String? value) {
    if (value == null || value.isEmpty) {
      return 'Authentication key is required';
    }
    if (value.length != 32) {
      return 'Key must be exactly 32 hex characters';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'Key must contain only hex characters (0-9, A-F)';
    }
    return null;
  }

  /// Check if all form inputs are valid
  bool _isFormValid() {
    return _validateSector(_sectorController.text) == null &&
           _validateBlock(_blockController.text) == null &&
           _validateBytePosition(_fbpController.text, 'FBP') == null &&
           _validateBytePosition(_lbpController.text, 'LBP') == null &&
           _validateAuthKey(_keyController.text) == null;
  }

  /// Show validation errors in a dialog
  void _showValidationErrors() {
    final errors = <String>[];
    
    final sectorError = _validateSector(_sectorController.text);
    if (sectorError != null) errors.add(sectorError);
    
    final blockError = _validateBlock(_blockController.text);
    if (blockError != null) errors.add(blockError);
    
    final fbpError = _validateBytePosition(_fbpController.text, 'FBP');
    if (fbpError != null) errors.add(fbpError);
    
    final lbpError = _validateBytePosition(_lbpController.text, 'LBP');
    if (lbpError != null) errors.add(lbpError);
    
    final keyError = _validateAuthKey(_keyController.text);
    if (keyError != null) errors.add(keyError);

    if (errors.isNotEmpty) {
      showDialog(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Validation Errors'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: errors.map((error) => Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(Icons.error, color: Colors.red, size: 16),
                  const SizedBox(width: 8),
                  Expanded(child: Text(error)),
                ],
              ),
            )).toList(),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('OK'),
            ),
          ],
        ),
      );
    }
  }

  /// Get the command code based on current settings (31h, 32h, 33h only)
  String _getCommandCode() {
    // MAC on command is always true, so we only use 31h, 32h, 33h
    if (_isPlaintext) {
      return _requiresMacOnResponse ? "33h" : "32h";
    } else {
      return "31h"; // Encrypted data always has MAC on response for security
    }
  }

  /// Get description of current command code
  String _getCommandDescription() {
    final code = _getCommandCode();
    final descriptions = {
      "31h": "MAC on command, Encrypted data, MAC on response",
      "32h": "MAC on command, Plaintext data, No MAC on response",
      "33h": "MAC on command, Plaintext data, MAC on response",
    };
    return descriptions[code] ?? "Unknown command";
  }

  // Decode the raw output using the selected format
  Future<void> _decodeData() async {
    if (_resultController.text.isEmpty || _resultController.text.startsWith('Error:')) {
      setState(() {
        _decodedController.text = 'No data to decode';
      });
      return;
    }

    setState(() {
      _isDecoding = true;
    });
    
    try {
      // Parse FBP and LBP as decimal values (byte positions)
      final fbp = int.tryParse(_fbpController.text) ?? 0;
      final lbp = int.tryParse(_lbpController.text) ?? 15;

      String result;
      if (_selectedFormat == 'BIN') {
        result = BinaryConversion.toBinary(_resultController.text, fbp, lbp);
      } else if (_selectedFormat == 'ASCII') {
        result = BinaryConversion.toASCII(_resultController.text, fbp, lbp);
      } else {
        result = BinaryConversion.toHex(_resultController.text, fbp, lbp);
      }
      
      setState(() {
        _decodedController.text = result;
      });
      
    } catch (error) {
      setState(() {
        _decodedController.text = 'Decode error: $error';
      });
    } finally {
      setState(() {
        _isDecoding = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('MIFARE Plus Scanner'),
        backgroundColor: Colors.blue,
        foregroundColor: Colors.white,
      ),
      body: SafeArea(
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Header Card
                Card(
                  elevation: 4,
                  color: Colors.blue[50],
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Column(
                      children: [
                        const Icon(Icons.nfc, size: 48, color: Colors.blue),
                        const SizedBox(height: 8),
                        const Text(
                          'MIFARE Plus Card Reader',
                          style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            color: Colors.blue,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          'Read data from MIFARE Plus cards with AES authentication',
                          style: TextStyle(
                            fontSize: 14,
                            color: Colors.blue[700],
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Sector Input with validation (1-39)
                TextFormField(
                  controller: _sectorController,
                  decoration: const InputDecoration(
                    labelText: 'Sector (1-39)',
                    border: OutlineInputBorder(),
                    hintText: 'Enter sector number',
                    prefixIcon: Icon(Icons.folder),
                  ),
                  keyboardType: TextInputType.number,
                  validator: _validateSector,
                  inputFormatters: [
                    FilteringTextInputFormatter.digitsOnly,
                    LengthLimitingTextInputFormatter(2),
                  ],
                ),
                const SizedBox(height: 16),

                // Block Input with validation (0-14)
                TextFormField(
                  controller: _blockController,
                  decoration: const InputDecoration(
                    labelText: 'Block (0-14)',
                    border: OutlineInputBorder(),
                    hintText: 'Enter block number',
                    prefixIcon: Icon(Icons.apps),
                  ),
                  keyboardType: TextInputType.number,
                  validator: _validateBlock,
                  inputFormatters: [
                    FilteringTextInputFormatter.digitsOnly,
                    LengthLimitingTextInputFormatter(2),
                  ],
                ),
                const SizedBox(height: 16),

                // Byte Position Row
                Row(
                  children: [
                    Expanded(
                      child: TextFormField(
                        controller: _fbpController,
                        decoration: const InputDecoration(
                          labelText: 'FBP (0-15)',
                          border: OutlineInputBorder(),
                          hintText: 'First byte',
                          prefixIcon: Icon(Icons.first_page),
                        ),
                        keyboardType: TextInputType.number,
                        validator: (value) => _validateBytePosition(value, 'FBP'),
                        inputFormatters: [
                          FilteringTextInputFormatter.digitsOnly,
                          LengthLimitingTextInputFormatter(2),
                        ],
                      ),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: TextFormField(
                        controller: _lbpController,
                        decoration: const InputDecoration(
                          labelText: 'LBP (0-15)',
                          border: OutlineInputBorder(),
                          hintText: 'Last byte',
                          prefixIcon: Icon(Icons.last_page),
                        ),
                        keyboardType: TextInputType.number,
                        validator: (value) => _validateBytePosition(value, 'LBP'),
                        inputFormatters: [
                          FilteringTextInputFormatter.digitsOnly,
                          LengthLimitingTextInputFormatter(2),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                // FBP > LBP info card
                if (_fbpController.text.isNotEmpty && _lbpController.text.isNotEmpty)
                  Builder(
                    builder: (context) {
                      final fbp = int.tryParse(_fbpController.text);
                      final lbp = int.tryParse(_lbpController.text);
                      if (fbp != null && lbp != null && fbp > lbp) {
                        return Card(
                          color: Colors.amber.withOpacity(0.1),
                          child: Padding(
                            padding: const EdgeInsets.all(12.0),
                            child: Row(
                              children: [
                                const Icon(Icons.info, color: Colors.amber),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: Text(
                                    'FBP > LBP: Data will be read in reverse order',
                                    style: TextStyle(
                                      color: Colors.amber[800],
                                      fontWeight: FontWeight.w500,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        );
                      }
                      return const SizedBox.shrink();
                    },
                  ),
                const SizedBox(height: 16),

                // Key Type Dropdown
                DropdownButtonFormField<String>(
                  value: _selectedKeyType,
                  decoration: const InputDecoration(
                    labelText: 'Key Type',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.vpn_key),
                  ),
                  items: _keyTypes.map((String keyType) {
                    return DropdownMenuItem<String>(
                      value: keyType,
                      child: Text(keyType),
                    );
                  }).toList(),
                  onChanged: (String? newValue) {
                    if (newValue != null) {
                      setState(() {
                        _selectedKeyType = newValue;
                      });
                    }
                  },
                  validator: (value) => value == null ? 'Please select a key type' : null,
                ),
                const SizedBox(height: 16),

                // Authentication Key Input with validation
                TextFormField(
                  controller: _keyController,
                  decoration: InputDecoration(
                    labelText: 'Authentication Key (32 hex chars)',
                    border: const OutlineInputBorder(),
                    hintText: 'Enter 32-character hex key',
                    prefixIcon: const Icon(Icons.security),
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.clear),
                      onPressed: () => _keyController.clear(),
                      tooltip: 'Clear key',
                    ),
                    helperText: 'Format: 0-9, A-F (case insensitive)',
                    errorMaxLines: 2,
                  ),
                  maxLength: 32,
                  validator: _validateAuthKey,
                  inputFormatters: [
                    FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F]')),
                    UpperCaseTextFormatter(),
                  ],
                ),
                const SizedBox(height: 24),

                // MIFARE Plus Communication Settings Section
                Card(
                  elevation: 2,
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Communication Settings',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        const SizedBox(height: 16),
                        
                        DropdownButtonFormField<String>(
                          value: _communicationType,
                          decoration: const InputDecoration(
                            labelText: 'Communication Type',
                            border: OutlineInputBorder(),
                            prefixIcon: Icon(Icons.lock_open),
                            helperText: 'Select data transmission mode',
                          ),
                          items: _communicationTypes.map((String type) {
                            return DropdownMenuItem<String>(
                              value: type,
                              child: Row(
                                children: [
                                  Icon(
                                    type == 'Plaintext' ? Icons.lock_open : Icons.lock,
                                    size: 16,
                                    color: type == 'Plaintext' ? Colors.orange : Colors.green,
                                  ),
                                  const SizedBox(width: 8),
                                  Text(type),
                                ],
                              ),
                            );
                          }).toList(),
                          onChanged: (String? newValue) {
                            if (newValue != null) {
                              setState(() {
                                _communicationType = newValue;
                              });
                            }
                          },
                        ),

                        const SizedBox(height: 16),

                        // Response Type Dropdown
                        DropdownButtonFormField<String>(
                          value: _responseType,
                          decoration: const InputDecoration(
                            labelText: 'Response Authentication',
                            border: OutlineInputBorder(),
                            prefixIcon: Icon(Icons.security),
                            helperText: 'Select response MAC requirement',
                          ),
                          items: _responseTypes.map((String type) {
                            return DropdownMenuItem<String>(
                              value: type,
                              child: Row(
                                children: [
                                  Icon(
                                    type == 'MAC on Response' ? Icons.verified_user : Icons.no_encryption,
                                    size: 16,
                                    color: type == 'MAC on Response' ? Colors.green : Colors.grey,
                                  ),
                                  const SizedBox(width: 8),
                                  Text(type),
                                ],
                              ),
                            );
                          }).toList(),
                          onChanged: (String? newValue) {
                            if (newValue != null) {
                              setState(() {
                                _responseType = newValue;
                              });
                            }
                          },
                        ),

                        const SizedBox(height: 16),

                        // Command Code Display
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.grey[100],
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: Colors.grey[300]!),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  const Icon(Icons.code, size: 16, color: Colors.grey),
                                  const SizedBox(width: 8),
                                  Text(
                                    'Command Code: ${_getCommandCode()}',
                                    style: const TextStyle(
                                      fontWeight: FontWeight.bold,
                                      fontFamily: 'monospace',
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 4),
                              Text(
                                _getCommandDescription(),
                                style: TextStyle(
                                  fontSize: 12,
                                  color: Colors.grey[600],
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Scan Button with validation
                ElevatedButton(
                  onPressed: _isScanning ? null : () async {
                    // Validate form first
                    if (!_formKey.currentState!.validate()) {
                      _showValidationErrors();
                      return;
                    }

                    setState(() {
                      _isScanning = true;
                      _resultController.text = 'Scanning...';
                    });

                    try {
                      // Convert key type string to integer (0 for Key A, 1 for Key B)
                      final keyTypeInt = _selectedKeyType == 'Key A' ? 0 : 1;
                      
                      final plusServices = PlusServices(debugMode: true);
                      final result = await plusServices.readPlus(
                        int.parse(_sectorController.text),
                        int.parse(_blockController.text),
                        KeyType.values[keyTypeInt],
                        _keyController.text,
                        isPlaintext: _isPlaintext,
                        requiresMacOnResponse: _requiresMacOnResponse,
                      );
                      
                      setState(() {
                        if (result.isSuccess) {
                          _resultController.text = result.data!;
                        } else {
                          final errorMsg = result is PlusError<String> ? result.message : null;
                          _resultController.text = errorMsg ?? 'Error: ${result.errorCode?.description} (${result.errorCode?.code})';
                        }
                        _decodedController.clear(); // Clear previous decoded data
                      });
                    } catch (e) {
                      setState(() {
                        _resultController.text = 'Error: $e';
                      });
                    } finally {
                      setState(() {
                        _isScanning = false;
                      });
                    }
                  },
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    backgroundColor: _isFormValid() ? Colors.blue : Colors.grey,
                    foregroundColor: Colors.white,
                  ),
                  child: _isScanning
                      ? const Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                              ),
                            ),
                            SizedBox(width: 12),
                            Text(
                              'Scanning...',
                              style: TextStyle(fontSize: 18),
                            ),
                          ],
                        )
                      : Text(
                          'Read MIFARE Plus Card (${_getCommandCode()})',
                          style: const TextStyle(fontSize: 18),
                        ),
                ),
                const SizedBox(height: 24),

                // Raw output area
                TextFormField(
                  controller: _resultController,
                  decoration: const InputDecoration(
                    labelText: 'Raw Data',
                    border: OutlineInputBorder(),
                    hintText: 'Raw scan data will appear here...',
                    prefixIcon: Icon(Icons.data_object),
                  ),
                  readOnly: true,
                  maxLines: 3,
                  style: const TextStyle(
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 24),

                // Decode section
                Row(
                  children: [
                    ElevatedButton(
                      onPressed: _isDecoding ? null : _decodeData,
                      child: _isDecoding
                          ? const SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Text('Decode'),
                    ),
                    const SizedBox(width: 16),
                    DropdownButton<String>(
                      value: _selectedFormat,
                      items: _formats.map((String format) {
                        return DropdownMenuItem<String>(
                          value: format,
                          child: Text(format),
                        );
                      }).toList(),
                      onChanged: (String? newValue) {
                        if (newValue != null) {
                          setState(() {
                            _selectedFormat = newValue;
                          });
                        }
                      },
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                // Decoded output area
                TextFormField(
                  controller: _decodedController,
                  decoration: const InputDecoration(
                    labelText: 'Decoded Data',
                    border: OutlineInputBorder(),
                    hintText: 'Decoded data will appear here...',
                    prefixIcon: Icon(Icons.translate),
                  ),
                  readOnly: true,
                  maxLines: 10,
                  style: const TextStyle(
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 24),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
