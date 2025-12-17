import "pe"

rule MAL_Compromised_Cert_ValleyRAT_DigiCert_0F4B2115767EFD289B85292362B118AE {
   meta:
      description         = "Detects ValleyRAT with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-03"
      version             = "1.0"

      hash                = "123baf5762064dac90572c7d7815f47ad4dc930b0ee2f14939cac54378cb25d9"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "咸宁创翼互联网科技有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0f:4b:21:15:76:7e:fd:28:9b:85:29:23:62:b1:18:ae"
      cert_thumbprint     = "CFAAF563A96933C9DFAD66549DA2A793A946F7E0"
      cert_valid_from     = "2025-07-03"
      cert_valid_to       = "2025-07-16"

      country             = "CN"
      state               = "湖北省"
      locality            = "咸宁市"
      email               = "???"
      rdn_serial_number   = "91422300MAEA9BX51L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0f:4b:21:15:76:7e:fd:28:9b:85:29:23:62:b1:18:ae"
      )
}
