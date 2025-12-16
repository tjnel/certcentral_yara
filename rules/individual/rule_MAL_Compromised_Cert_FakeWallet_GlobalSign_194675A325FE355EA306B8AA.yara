import "pe"

rule MAL_Compromised_Cert_FakeWallet_GlobalSign_194675A325FE355EA306B8AA {
   meta:
      description         = "Detects FakeWallet with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-05"
      version             = "1.0"

      hash                = "fc858ad30e1607f8d08f0d470b6f29d02b478651128b0ef9e6a5c91519e04862"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MALA ENGICON PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "19:46:75:a3:25:fe:35:5e:a3:06:b8:aa"
      cert_thumbprint     = "F58533B6EA727C1D81E7CD473B4E207D481732DC"
      cert_valid_from     = "2025-06-05"
      cert_valid_to       = "2026-06-06"

      country             = "IN"
      state               = "Bihar"
      locality            = "Samastipur"
      email               = "souravkumarmengicon@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "19:46:75:a3:25:fe:35:5e:a3:06:b8:aa"
      )
}
