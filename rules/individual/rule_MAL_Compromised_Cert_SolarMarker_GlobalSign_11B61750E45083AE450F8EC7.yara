import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_11B61750E45083AE450F8EC7 {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-11-15"
      version             = "1.0"

      hash                = "be1d635e6325a67ea4cbab84066e56e76a28c7c5ca26abdf466860cf11010e1f"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Jiazhou Education & Consulting Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "11:b6:17:50:e4:50:83:ae:45:0f:8e:c7"
      cert_thumbprint     = "F6149648C93494A65FFD4E8664147E79AAA051E8"
      cert_valid_from     = "2022-11-15"
      cert_valid_to       = "2023-11-10"

      country             = "CA"
      state               = "Ontario"
      locality            = "Waterloo"
      email               = "???"
      rdn_serial_number   = "1005614-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "11:b6:17:50:e4:50:83:ae:45:0f:8e:c7"
      )
}
