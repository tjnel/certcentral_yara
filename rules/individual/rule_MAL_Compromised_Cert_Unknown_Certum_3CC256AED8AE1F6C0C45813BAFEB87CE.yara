import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_3CC256AED8AE1F6C0C45813BAFEB87CE {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-31"
      version             = "1.0"

      hash                = "daf28c33a9cb1d8186fc2bf78613cf4131941812e081facc2ad7d29f4af10808"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jinan Yuejing Electronic Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "3c:c2:56:ae:d8:ae:1f:6c:0c:45:81:3b:af:eb:87:ce"
      cert_thumbprint     = "A64479F3815B4646277E862F3158B0C17485F72E"
      cert_valid_from     = "2024-07-31"
      cert_valid_to       = "2025-07-31"

      country             = "CN"
      state               = "Shandong"
      locality            = "Jinan"
      email               = "???"
      rdn_serial_number   = "91370102MA3C9D0U34"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "3c:c2:56:ae:d8:ae:1f:6c:0c:45:81:3b:af:eb:87:ce"
      )
}
