import "pe"

rule MAL_Compromised_Cert_DarkGate_Certum_762823EF38B0B322B5DF2ABDF1A735CC {
   meta:
      description         = "Detects DarkGate with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-20"
      version             = "1.0"

      hash                = "0cfbfec5f04e23ec34ab02788af1d2cb153f8ea45e52a1a16c759ba25ed9d90a"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "Shenzhen Julishun Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "76:28:23:ef:38:b0:b3:22:b5:df:2a:bd:f1:a7:35:cc"
      cert_thumbprint     = "3128120C9933BF1FF8422AE0641150E6DC070829"
      cert_valid_from     = "2024-06-20"
      cert_valid_to       = "2025-06-20"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "914403003265237255"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "76:28:23:ef:38:b0:b3:22:b5:df:2a:bd:f1:a7:35:cc"
      )
}
