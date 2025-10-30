#include <cstdint>
#include <format>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

// Function to truncate ciphertexts to the size of the target
std::vector<std::string>
truncateToTargetSize(const std::vector<std::string> &ciphertexts,
                     const std::string &target) {
  std::vector<std::string> truncated;
  size_t target_size = target.size();

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
  const std::string &target_ciphertext = ciphertexts[target_index];

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
  std::vector<std::string> truncated_ciphertexts =
      truncateToTargetSize(analysis_ciphertexts, target_ciphertext);

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
  std::vector<uint8_t> target_bytes = hexStringToBytes(target_ciphertext);
  std::cout << "Target ciphertext as bytes: " << target_bytes.size() << " bytes"
            << std::endl;

  // XOR each ciphertext with target and process results
  std::cout << "\nXORing ciphertexts with target:" << std::endl;

  // std::string result(target_bytes.size(), '_');
  std::string result = "The "
                       "secret message is_______using___stream cipher__never "
                       "use the key more than once";

  std::vector<std::string> alternative_results;
  std::vector<std::set<std::uint8_t>> possible_chars(target_bytes.size(),
                                                     std::set<std::uint8_t>());

  for (size_t i = 0; i < truncated_ciphertexts.size(); ++i) {
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

  std::cout << result << std::endl;
  for (const auto &alt_res : alternative_results) {
    std::cout << alt_res << std::endl;
  }

  return 0;
}
