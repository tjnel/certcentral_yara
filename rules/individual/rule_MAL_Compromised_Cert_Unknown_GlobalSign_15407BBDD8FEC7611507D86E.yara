import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_15407BBDD8FEC7611507D86E {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-13"
      version             = "1.0"

      hash                = "bd49ac4b03b17dd3b6ce9d30b2e88ba4b226baf9aaa9a3284b39c97b80643b96"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuhan Branch of Anhui Blade Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "15:40:7b:bd:d8:fe:c7:61:15:07:d8:6e"
      cert_thumbprint     = "C1A0706B5FE40289094E2E135CEC29979683F9CE"
      cert_valid_from     = "2023-07-13"
      cert_valid_to       = "2024-08-28"

      country             = "CN"
      state               = "Hubei"
      locality            = "Wuhan"
      email               = "???"
      rdn_serial_number   = "91420100MA7KRK4A7W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "15:40:7b:bd:d8:fe:c7:61:15:07:d8:6e"
      )
}
