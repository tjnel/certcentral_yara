import "pe"

rule MAL_Compromised_Cert_Xworm_GlobalSign_6BF56A335E58AE8C94C8C99D {
   meta:
      description         = "Detects Xworm with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-18"
      version             = "1.0"

      hash                = "0467ee83070e28023faf9b096a7710b9b58a4b3b937b80cb3406e30b9fbee853"
      malware             = "Xworm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Pay 2 Services Company Limited"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6b:f5:6a:33:5e:58:ae:8c:94:c8:c9:9d"
      cert_thumbprint     = "4C4DD9838D8862724A9BE9F7142B7D6A5632BB18"
      cert_valid_from     = "2024-11-18"
      cert_valid_to       = "2025-11-19"

      country             = "VN"
      state               = "Hồ Chí Minh"
      locality            = "Hồ Chí Minh"
      email               = "???"
      rdn_serial_number   = "0314605239"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6b:f5:6a:33:5e:58:ae:8c:94:c8:c9:9d"
      )
}
