import "pe"

rule MAL_Compromised_Cert_DPRK_Generic_Sectigo_00B7EBC31DF472A506A4234525BD51157C {
   meta:
      description         = "Detects DPRK Generic with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-09"
      version             = "1.0"

      hash                = "77877a13d22fbbdce452791f3015823a3e9b1b48b3cdeb20c118814bfd9072b9"
      malware             = "DPRK Generic"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ezhou Taihaocheng Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b7:eb:c3:1d:f4:72:a5:06:a4:23:45:25:bd:51:15:7c"
      cert_thumbprint     = "79A462C7E6ECE7714E99D600B93A2B4927C13846"
      cert_valid_from     = "2025-06-09"
      cert_valid_to       = "2026-06-09"

      country             = "CN"
      state               = "Hubei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91420702MAD5FYH837"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b7:eb:c3:1d:f4:72:a5:06:a4:23:45:25:bd:51:15:7c"
      )
}
