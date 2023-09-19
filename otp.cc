#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <cstddef>
#include <cstdint>
#include <ctime>

#include "openssl/evp.h"
#include "openssl/hmac.h"

std::vector<std::uint8_t> hmac_sha1(const std::vector<std::uint8_t>& key,
                                    const std::vector<std::uint8_t>& data) {
  std::uint8_t buf[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  HMAC(EVP_sha1(),
       key.data(),
       static_cast<int>(key.size()),
       data.data(),
       data.size(),
       buf,
       &len);
  return {buf, buf + len};
}

/* uint64 to binary (big endian) */
std::vector<std::uint8_t> u64_2bin_be(const std::uint64_t& u64) {
  std::vector<std::uint8_t> bin_be;
  for (int i = 7; i >= 0; i--) {
    bin_be.emplace_back(static_cast<std::uint8_t>((u64 >> (8 * i)) & 0xff));
  }
  return bin_be;
}

std::string gen_hotp(const std::vector<uint8_t>& secret,
                     const std::uint64_t& counter,
                     const int& digits) {
  std::vector<std::uint8_t> hash = hmac_sha1(secret, u64_2bin_be(counter));
  std::size_t offset = hash[hash.size() - 1] & 0xf;
  /* clang-format off */
  int otp = ((hash[offset]     & 0x7f) << 24)
          | ((hash[offset + 1] & 0xff) << 16)
          | ((hash[offset + 2] & 0xff) << 8)
          |  (hash[offset + 3] & 0xff);
  /* clang-format on */
  char otp_str[digits + 1];
  otp_str[digits] = '\0';
  for (int i = digits; i > 0; i--) {
    otp_str[i - 1] = static_cast<char>((otp % 10) + '0');
    otp /= 10;
  }
  return otp_str;
}

std::uint64_t get_unix_time_seconds() {
  return static_cast<std::uint64_t>(std::time(nullptr));
}

std::string gen_totp(const std::vector<std::uint8_t>& secret,
                     const std::uint64_t& seconds,
                     const std::uint64_t& period,
                     const int& digits) {
  return gen_hotp(secret, seconds / period, digits);
}

std::string gen_totp_now(const std::vector<std::uint8_t>& secret,
                         const std::uint64_t& period,
                         const int& digits) {
  return gen_totp(secret, get_unix_time_seconds(), period, digits);
}

std::string b32enc(const std::vector<std::uint8_t>& data) {
  static const char b32str[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  std::string b32;
  b32.reserve(((data.size() * 8) / 5) + 1);
  std::size_t data_len = data.size();
  std::size_t i = 0;
  int npad = 0;
  // every 5 bytes
  while (data_len > 0) {
    /* 00000000 ???????? ???????? ???????? ????????
     * ^^^^^                                        */
    b32.push_back(b32str[(data[i] >> 3) & 0b00011111]);
    data_len--;

    if (data_len > 0) {
      /* 00000000 00000000 ???????? ???????? ????????
       *      ^^^ ^^                                  */
      b32.push_back(b32str[(((data[i] << 2) & 0b00011100)
                            | ((data[i + 1] >> 6) & 0b00000011))
                           & 0b00011111]);
      /* 00000000 00000000 ???????? ???????? ????????
       *            ^^^^^                             */
      b32.push_back(b32str[(data[i + 1] >> 1) & 0b00011111]);
      data_len--;
    }
    else {
      /* 00000000 -------- -------- -------- --------
       *      ^^^ 00                                  */
      b32.push_back(b32str[((data[i] << 2) & 0b00011100) & 0b00011111]);
      npad = 6;
      break;
    }

    if (data_len > 0) {
      /* 00000000 00000000 00000000 ???????? ????????
       *                 ^ ^^^^                       */
      b32.push_back(b32str[(((data[i + 1] << 4) & 0b00010000)
                            | ((data[i + 2] >> 4) & 0b00001111))
                           & 0b00011111]);
      data_len--;
    }
    else {
      /* 00000000 00000000 -------- -------- --------
       *                 ^ 0000                       */
      b32.push_back(b32str[((data[i + 1] << 4) & 0b00010000) & 0b00011111]);
      npad = 4;
      break;
    }

    if (data_len > 0) {
      /* 00000000 00000000 00000000 00000000 ????????
       *                       ^^^^ ^                 */
      b32.push_back(b32str[(((data[i + 2] << 1) & 0b00011110)
                            | ((data[i + 3] >> 7) & 0b00000001))
                           & 0b00011111]);
      /* 00000000 00000000 00000000 00000000 ????????
       *                             ^^^^^            */
      b32.push_back(b32str[(data[i + 3] >> 2) & 0b00011111]);
      data_len--;
    }
    else {
      /* 00000000 00000000 00000000 -------- --------
       *                       ^^^^ 0                 */
      b32.push_back(b32str[((data[i + 2] << 1) & 0b00011110) & 0b00011111]);
      npad = 3;
      break;
    }

    if (data_len > 0) {
      /* 00000000 00000000 00000000 00000000 00000000
       *                                  ^^ ^^^      */
      b32.push_back(b32str[(((data[i + 3] << 3) & 0b00011000)
                            | ((data[i + 4] >> 5) & 0b00000111))
                           & 0b00011111]);
      /* 00000000 00000000 00000000 00000000 00000000
       *                                        ^^^^^ */
      b32.push_back(b32str[data[i + 4] & 0b00011111]);
      data_len--;
    }
    else {
      /* 00000000 00000000 00000000 00000000 --------
       *                                  ^^ 000      */
      b32.push_back(b32str[((data[i + 3] << 3) & 0b00011000) & 0b00011111]);
      npad = 1;
      break;
    }

    i += 5;
  }

  for (; npad > 0; npad--) {
    b32.push_back('=');
  }

  return b32;
}

// return the binary value of base32 character `c`
constexpr std::uint8_t b32table(const char& c) {
  switch (c) {
  case 'A': return 0; break;
  case 'B': return 1; break;
  case 'C': return 2; break;
  case 'D': return 3; break;
  case 'E': return 4; break;
  case 'F': return 5; break;
  case 'G': return 6; break;
  case 'H': return 7; break;
  case 'I': return 8; break;
  case 'J': return 9; break;
  case 'K': return 10; break;
  case 'L': return 11; break;
  case 'M': return 12; break;
  case 'N': return 13; break;
  case 'O': return 14; break;
  case 'P': return 15; break;
  case 'Q': return 16; break;
  case 'R': return 17; break;
  case 'S': return 18; break;
  case 'T': return 19; break;
  case 'U': return 20; break;
  case 'V': return 21; break;
  case 'W': return 22; break;
  case 'X': return 23; break;
  case 'Y': return 24; break;
  case 'Z': return 25; break;
  case '2': return 26; break;
  case '3': return 27; break;
  case '4': return 28; break;
  case '5': return 29; break;
  case '6': return 30; break;
  case '7': return 31; break;
  case '=': return 32; break;
  default: return 0xff; break;
  }
}

// convert base32 character `c` to binary and save it to `bin5b`
// return false if `c` is '=' or not a valid base32 character
constexpr bool b32bin(const char& c, std::uint8_t& bin5b) {
  bin5b = b32table(c);
  return (bin5b & 0b11100000) == 0;
}

std::vector<std::uint8_t> b32dec(const std::string& b32) {
  std::vector<std::uint8_t> data;
  data.reserve((b32.length() * 5) / 8);
  std::size_t b32len = b32.length();
  std::size_t i = 0;
  std::uint8_t byte = 0;
  // 5 bits from a b32 character
  std::uint8_t bin5b = 0;
  // every 8 b32 characters
  while (b32len > 0 && b32bin(b32[i], bin5b)) {
    /* 00000 ???|?? ????? ?|???? ????|? ????? ??|??? ?????
     * ^^^^^    |          |         |          |          */
    byte |= ((bin5b << 3) & 0b11111000);
    b32len--;

    if (b32len > 0 && b32bin(b32[i + 1], bin5b)) {
      /* 00000 000|00 ????? ?|???? ????|? ????? ??|??? ?????
       *       ^^^|          |         |          |          */
      byte |= ((bin5b >> 2) & 0b00000111);
      data.push_back(byte);
      byte = 0;
      /* 00000 000|00 ????? ?|???? ????|? ????? ??|??? ?????
       *          |^^        |         |          |          */
      byte |= ((bin5b << 6) & 0b11000000);
      b32len--;
    }
    else {
      /* 00000 ---|-- ----- -|---- ----|- ----- --|--- -----
       *       000|          |         |          |          */
      data.push_back(byte);
      break;
    }

    if (b32len > 0 && b32bin(b32[i + 2], bin5b)) {
      /* 00000 000|00 00000 ?|???? ????|? ????? ??|??? ?????
       *          |   ^^^^^  |         |          |          */
      byte |= ((bin5b << 1) & 0b00111110);
      b32len--;
    }
    else {
      /* 00000 000|00 ----- -|---- ----|- ----- --|--- -----
       *          |   00000 0|         |          |          */
      if (byte != 0) {
        // not a pad
        data.push_back(byte);
      }
      break;
    }

    if (b32len > 0 && b32bin(b32[i + 3], bin5b)) {
      /* 00000 000|00 00000 0|0000 ????|? ????? ??|??? ?????
       *          |         ^|         |          |          */
      byte |= ((bin5b >> 4) & 0b00000001);
      data.push_back(byte);
      byte = 0;
      /* 00000 000|00 00000 0|0000 ????|? ????? ??|??? ?????
       *          |          |^^^^     |          |          */
      byte |= ((bin5b << 4) & 0b11110000);
      b32len--;
    }
    else {
      /* 00000 000|00 00000 -|---- ----|- ----- --|--- -----
       *          |         0|         |          |          */
      data.push_back(byte);
      break;
    }

    if (b32len > 0 && b32bin(b32[i + 4], bin5b)) {
      /* 00000 000|00 00000 0|0000 0000|0 ????? ??|??? ?????
       *          |          |     ^^^^|          |          */
      byte |= ((bin5b >> 1) & 0b00001111);
      data.push_back(byte);
      byte = 0;
      /* 00000 000|00 00000 0|0000 0000|0 ????? ??|??? ?????
       *          |          |         |^         |          */
      byte |= ((bin5b << 7) & 0b10000000);
      b32len--;
    }
    else {
      /* 00000 000|00 00000 0|0000 ----|- ----- --|--- -----
       *          |          |     0000|          |          */
      if (byte != 0) {
        data.push_back(byte);
      };
      break;
    }

    if (b32len > 0 && b32bin(b32[i + 5], bin5b)) {
      /* 00000 000|00 00000 0|0000 0000|0 00000 ??|??? ?????
       *          |          |         |  ^^^^^   |          */
      byte |= ((bin5b << 2) & 0b01111100);
      b32len--;
    }
    else {
      /* 00000 000|00 00000 0|0000 0000|0 ----- --|--- -----
       *          |          |         |  00000 00|          */
      if (byte != 0) {
        data.push_back(byte);
      }
      break;
    }

    if (b32len > 0 && b32bin(b32[i + 6], bin5b)) {
      /* 00000 000|00 00000 0|0000 0000|0 00000 00|000 ?????
       *          |          |         |        ^^|          */
      byte |= ((bin5b >> 3) & 0b00000011);
      data.push_back(byte);
      byte = 0;
      /* 00000 000|00 00000 0|0000 0000|0 00000 00|000 ?????
       *          |          |         |          |^^^       */
      byte |= ((bin5b << 5) & 0b11100000);
      b32len--;
    }
    else {
      /* 00000 000|00 00000 0|0000 0000|0 00000 --|--- -----
       *          |          |         |        00|          */
      data.push_back(byte);
      break;
    }

    if (b32len > 0 && b32bin(b32[i + 7], bin5b)) {
      /* 00000 000|00 00000 0|0000 0000|0 00000 00|000 00000
       *          |          |         |          |    ^^^^^ */
      byte |= (bin5b & 0b00011111);
      data.push_back(byte);
      byte = 0;
      b32len--;
    }
    else {
      /* 00000 000|00 00000 0|0000 0000|0 00000 00|000 -----
       *          |          |         |          |    00000 */
      if (byte != 0) {
        data.push_back(byte);
      }
      break;
    }

    i += 8;
  }
  return data;
}

int main(int argc, const char* argv[]) {
  std::string secret_b32;
  std::cout << "Paste Github secret (Base32 encoded): " << std::flush;
  std::cin >> secret_b32;
  std::vector<std::uint8_t> secret = b32dec(secret_b32);
  std::cout << "TOTP: " << std::flush;
  while (true) {
    std::cout << gen_totp_now(secret, 30, 6);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << "\b\b\b\b\b\b" << std::flush;
  }
  return 0;
}
