/*
DISCLAIMER: This code is provided "as is" without any guarantees or warranty.

THIS CODE IS A NIGHTMARE, JUST MADE IT TO SOLVE THE ASSIGNMENT, DO NOT USE AS
REFERENCE.
*/

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iostream>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple> // structured bindings of tuple-like sometimes need this with some libstdc++
#include <vector>

// Function to truncate ciphertexts to the size of the target
std::vector<std::string>
truncateToTargetSize(const std::vector<std::string> &ciphertexts,
                     size_t target_size) {
  std::vector<std::string> truncated;

  for (const auto &cipher : ciphertexts) {
    if (cipher.size() > target_size) {
      truncated.push_back(cipher.substr(0, target_size));
    } else {
      truncated.push_back(cipher);
    }
  }

  return truncated;
}

// Function to convert hex string to bytes
std::vector<uint8_t> hexStringToBytes(const std::string &hex) {
  std::vector<uint8_t> bytes;

  // Ensure the string has even length
  if (hex.length() % 2 != 0) {
    throw std::invalid_argument("Hex string must have even length");
  }

  for (size_t i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}

int main(int argc, char *argv[]) {
  std::vector<std::vector<uint8_t>> supposed_keys(11, std::vector<uint8_t>());
  supposed_keys[0] = {0x66, 0x39, 0x6e, 0x89, 0xc9, 0xdb, 0xd8, 0xcc, 0x98,
                      0x74, 0x35, 0x2a, 0xcd, 0x63, 0x95, 0x10, 0x2e, 0xaf,
                      0xce, 0x78, 0xaa, 0x7f, 0xed, 0x28, 0x00, 0x00, 0x00,
                      0x00, 0x8d, 0x29, 0xc5, 0x0b, 0x69, 0xb0, 0x33, 0x9a,
                      0x19, 0xf8, 0xaa, 0x40, 0x1a, 0x9c, 0x6d, 0x70, 0x8f,
                      0x80, 0xc0, 0x66, 0xc7, 0x00, 0x00, 0x00, 0x12, 0x31,
                      0x48, 0xcd, 0xd8, 0xe8, 0x02, 0xd0, 0x5b, 0xa9, 0x87,
                      0x77, 0x33, 0x5d, 0xae, 0xfc, 0xec, 0xd5, 0x9c, 0x43,
                      0x3a, 0x6b, 0x26, 0x8b, 0x60, 0xbf, 0x4e, 0xf0, 0x3c,
                      0x9a, 0x61},
  supposed_keys[1] = {0x66, 0x39, 0x6e, 0x89, 0xc9, 0xdb, 0xd8, 0xcc, 0x98,
                      0x74, 0x35, 0x2a, 0xcd, 0x63, 0x95, 0x10, 0x2e, 0xaf,
                      0xce, 0x78, 0xaa, 0x7f, 0xed, 0x28, 0xa0, 0x7f, 0x6b,
                      0xc9, 0x8d, 0x29, 0xc5, 0x0b, 0x69, 0xb0, 0x33, 0x9a,
                      0x19, 0xf8, 0xaa, 0x40, 0x1a, 0x9c, 0x6d, 0x70, 0x8f,
                      0x80, 0xc0, 0x66, 0xc7, 0x63, 0xfe, 0xf0, 0x12, 0x31,
                      0x48, 0xcd, 0xd8, 0xe8, 0x02, 0xd0, 0x5b, 0xa9, 0x87,
                      0x77, 0x33, 0x5d, 0xae, 0xfc, 0xec, 0xd5, 0x9c, 0x43,
                      0x3a, 0x6b, 0x26, 0x8b, 0x60, 0xbf, 0x4e, 0xf0, 0x00,
                      0x00, 0x00},
  supposed_keys[10] = {
      0x66, 0x39, 0x6e, 0x89, 0xc9, 0xdb, 0xd8, 0xcc, 0x98, 0x74, 0x35, 0x2a,
      0xcd, 0x63, 0x95, 0x10, 0x2e, 0xaf, 0xce, 0x78, 0xaa, 0x7f, 0xed, 0x28,
      0xa0, 0x7f, 0x6b, 0xc9, 0x8d, 0x29, 0xc5, 0x0b, 0x69, 0xb0, 0x33, 0x9a,
      0x19, 0xf8, 0xaa, 0x40, 0x1a, 0x9c, 0x6d, 0x70, 0x8f, 0x80, 0xc0, 0x66,
      0xc7, 0x63, 0xfe, 0xf0, 0x12, 0x31, 0x48, 0xcd, 0xd8, 0xe8, 0x02, 0xd0,
      0x5b, 0xa9, 0x87, 0x77, 0x33, 0x5d, 0xae, 0xfc, 0xec, 0xd5, 0x9c, 0x43,
      0x3a, 0x6b, 0x26, 0x8b, 0x60, 0xbf, 0x4e, 0xf0, 0x3c, 0x9a, 0x61};

  std::vector<uint8_t> mixed_key(supposed_keys[0].size(), 0x0);
  // Mixing strategy: For each position, if mixed_key is not zero, overwrite it
  // with the value from the current supposed_key. This attempts to combine
  // known key bytes from multiple sources, preferring non-zero values.
  for (const auto &supposed_key : supposed_keys) {
    for (size_t i = 0; i < supposed_key.size(); i++) {
      if (mixed_key[i] == 0x00) {
        mixed_key[i] = supposed_key[i];
      }
    }
  }
  mixed_key =
      supposed_keys[10]; // Use the key from the target ciphertext directly

  std::vector<std::string> ciphertexts = {
      // ciphertext #1
      "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb"
      "778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37"
      "520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbca"
      "a3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",

      // ciphertext #2
      "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba"
      "7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c"
      "5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cd"
      "adb8356f",

      // ciphertext #3
      "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba"
      "6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f325"
      "1a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",

      // ciphertext #4
      "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f4"
      "7a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63"
      "590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8da"
      "bbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aa"
      "a",

      // ciphertext #5
      "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f1"
      "7c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef37"
      "5f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dc"
      "aba43722130f042f8ec85b7c2070",

      // ciphertext #6
      "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba"
      "34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f963"
      "5c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0"
      "aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6"
      "cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",

      // ciphertext #7
      "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba"
      "7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e930"
      "5f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cc"
      "e2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270ab"
      "cf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313"
      "c8661dd9a4ce",

      // ciphertext #8
      "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba"
      "708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d"
      "5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2da"
      "ada43d6712150441c2e04f6565517f317da9d3",

      // ciphertext #9
      "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e9"
      "6d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836"
      "480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88"
      "a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e4"
      "8b63ab15d0208573a7eef027",

      // ciphertext #10
      "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3"
      "399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537"
      "530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",

      // ciphertext #11 (target ciphertext to decrypt)
      "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba"
      "6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f331"
      "5f4b52e301d16e9f52f904"};

  // Target ciphertext is at index 10 (11th element)
  const size_t target_index = 10;
  const size_t real_target_index = 10;
  // clang-format off
  std::vector<std::string> expected_results(11, "");
  expected_results[0]  =
      "We can factor the number____with quantum computer___We can also factor the number 1";
  expected_results[1]  =
      "Euler would probably enjoy that now his theorem becomes a corner stone of crypto___";
  expected_results[10] =
      "The secret message is: When using a stream cipher, never use the key more than once";
  // clang-format on
  std::string expected_result = expected_results[real_target_index];

  const std::string &target_ciphertext = ciphertexts[target_index];
  const std::string &real_target_ciphertext = ciphertexts[real_target_index];

  std::cout << "Loaded " << ciphertexts.size() << " ciphertexts for analysis"
            << std::endl;
  std::cout << "Target ciphertext (index " << target_index
            << ") length: " << target_ciphertext.size() << std::endl;

  // Create a vector of ciphertexts excluding the target for analysis
  std::vector<std::string> analysis_ciphertexts;
  for (size_t i = 0; i < ciphertexts.size(); ++i) {
    if (i != target_index) {
      analysis_ciphertexts.push_back(ciphertexts[i]);
    }
  }

  // Truncate all analysis ciphertexts to match target size
  std::vector<std::string> truncated_ciphertexts = truncateToTargetSize(
      analysis_ciphertexts,
      std::min(real_target_ciphertext.size(), target_ciphertext.size()));
  std::string truncated_target_ciphertext = target_ciphertext.substr(
      0, std::min(real_target_ciphertext.size(), target_ciphertext.size()));

  std::cout << "Truncated ciphertexts to target length:" << std::endl;
  for (size_t i = 0; i < truncated_ciphertexts.size(); ++i) {
    std::cout << "Ciphertext " << (i + 1)
              << " length: " << truncated_ciphertexts[i].size()
              << " (original: " << ciphertexts[i].size() << ")" << std::endl;
  }

  // Convert hex strings to bytes
  std::cout << "\nConverting hex strings to bytes..." << std::endl;

  std::vector<uint8_t> cipher_bytes;
  for (size_t i = 0; i < truncated_ciphertexts.size(); ++i) {
    std::vector<uint8_t> bytes = hexStringToBytes(truncated_ciphertexts[i]);
    std::cout << "Ciphertext " << (i + 1) << " as bytes: " << bytes.size()
              << " bytes" << std::endl;
  }

  // Convert target ciphertext to bytes
  std::vector<uint8_t> target_bytes =
      hexStringToBytes(truncated_target_ciphertext);
  std::cout << "Target ciphertext as bytes: " << target_bytes.size() << " bytes"
            << std::endl;

  // XOR each ciphertext with target and process results
  std::cout << "\nXORing ciphertexts with target:" << std::endl;

  std::string result(target_bytes.size(), '_');

  std::vector<std::string> alternative_results;
  std::vector<std::set<std::uint8_t>> possible_chars(target_bytes.size(),
                                                     std::set<std::uint8_t>());

  for (size_t i = 0; i < truncated_ciphertexts.size(); ++i) {
    if (i == target_index) {
      continue; // Skip the target itself
    }
    std::vector<uint8_t> cipher_bytes =
        hexStringToBytes(truncated_ciphertexts[i]);
    std::string alternative_result(target_bytes.size(), '_');
    bool got_alternative = false;

    // XOR each byte and process the result
    for (size_t j = 0; j < std::min(cipher_bytes.size(), target_bytes.size());
         ++j) {
      uint8_t xor_result = cipher_bytes[j] ^ target_bytes[j];

      // Check if result is in a-zA-Z range
      if ((xor_result >= 'a' && xor_result <= 'z') ||
          (xor_result >= 'A' && xor_result <= 'Z')) {
        // Swap case: lower to upper, upper to lower
        char ch;
        if (xor_result >= 'a' && xor_result <= 'z') {
          ch = static_cast<char>(xor_result - 'a' + 'A'); // lower to upper
        } else {
          ch = static_cast<char>(xor_result - 'A' + 'a'); // upper to lower
        }
        if (result[j] == '_') {
          result[j] = ch;
        } else if (result[j] != ch) {
          // Conflict, store in alternative result
          if (possible_chars[j].find(ch) == possible_chars[j].end()) {
            possible_chars[j].insert(ch);
            alternative_result[j] = ch;
            got_alternative = true;
          }
        }
      }
    }

    if (got_alternative) {
      alternative_results.push_back(alternative_result);
    }
  }

  // Convert real_result to bytes using modern C++23 ranges, replacing '_' with
  // 0x0
  auto real_result_bytes =
      expected_result | std::views::transform([](char c) -> uint8_t {
        return c == '_' ? uint8_t{0x0} : static_cast<uint8_t>(c);
      }) |
      std::ranges::to<std::vector>();

  // Convert real target ciphertext to bytes
  std::vector<uint8_t> real_target_bytes =
      hexStringToBytes(real_target_ciphertext);

  // Calculate the key by XORing known plaintext with target ciphertext
  // Where plaintext is unknown (0x00), set key to 0x00
  auto calculated_key =
      std::views::zip(real_result_bytes, target_bytes) |
      std::views::transform([](const auto &pair) -> uint8_t {
        auto [plain, cipher] = pair;
        return plain == 0 ? 0 : static_cast<uint8_t>(plain ^ cipher);
      }) |
      std::ranges::to<std::vector>();

  // Decrypt target ciphertext using calculated key where key is not 0
  // Where key is 0x0, use the result from XOR analysis
  auto decrypted_result =
      std::views::zip(target_bytes, calculated_key, result) |
      std::views::transform([](const auto &triple) -> char {
        auto [cipher, key, result_char] = triple;
        if (key == 0) {
          return result_char; // Use XOR analysis result when key is unknown
        }
        uint8_t decrypted_byte = cipher ^ key;
        // Return printable character or '_' if not printable
        return (decrypted_byte >= 32 && decrypted_byte <= 126)
                   ? static_cast<char>(decrypted_byte)
                   : '_';
      }) |
      std::ranges::to<std::string>();

  // Print the calculated key in copy-paste friendly formats
  std::cout << "\n=== CALCULATED KEY (Copy-Paste Ready) ===" << std::endl;

  // As C++ hex array initializer
  std::cout << "// C++ array initialization:" << std::endl;
  std::cout << "std::vector<uint8_t> key = {";
  for (size_t i = 0; i < calculated_key.size(); ++i) {
    if (i % 16 == 0)
      std::cout << "\n    ";
    std::cout << std::format("0x{:02x}", calculated_key[i]);
    if (i < calculated_key.size() - 1)
      std::cout << ", ";
  }
  std::cout << "\n};" << std::endl;

  // Decrypt target using the mixed_key
  auto target_with_mixed_key =
      std::views::zip(real_target_bytes, mixed_key) |
      std::views::transform([](const auto &pair) -> char {
        auto [cipher_byte, key_byte] = pair;
        uint8_t decrypted_byte = cipher_byte ^ key_byte;
        // Return printable character or '_' if not printable
        return (decrypted_byte >= 32 && decrypted_byte <= 126)
                   ? static_cast<char>(decrypted_byte)
                   : '_';
      }) |
      std::ranges::to<std::string>();

  std::cout << "\n=== RESULTS ===" << std::endl;
  std::cout << "Expected result:       " << expected_result << std::endl;
  std::cout << "Calculated decryption: " << decrypted_result << std::endl;
  std::cout << "Target with mixed key: " << target_with_mixed_key << std::endl;

  for (const auto &alt_res : alternative_results) {
    std::cout << alt_res << std::endl;
  }

  // Decrypt all ciphertexts using mixed_key
  std::cout << "\n=== ALL CIPHERTEXTS DECRYPTED WITH MIXED KEY ==="
            << std::endl;
  for (size_t i = 0; i < ciphertexts.size(); ++i) {
    std::vector<uint8_t> cipher_bytes = hexStringToBytes(ciphertexts[i]);

    auto decrypted_cipher =
        std::views::zip(cipher_bytes, mixed_key) |
        std::views::transform([](const auto &pair) -> char {
          auto [cipher_byte, key_byte] = pair;
          uint8_t decrypted_byte = cipher_byte ^ key_byte;
          // Return printable character or '_' if not printable
          return (decrypted_byte >= 32 && decrypted_byte <= 126)
                     ? static_cast<char>(decrypted_byte)
                     : '_';
        }) |
        std::ranges::to<std::string>();

    std::cout << "Ciphertext " << std::format("{:>2}", i + 1) << ": "
              << decrypted_cipher << std::endl;
  }

  return 0;
}
