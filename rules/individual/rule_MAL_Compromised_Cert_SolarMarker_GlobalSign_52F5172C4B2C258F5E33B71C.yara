import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_52F5172C4B2C258F5E33B71C {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-12"
      version             = "1.0"

      hash                = "c6fda8a049ebd7872358acfa2505f226e931e0f71090c19412e7b6d0a1c6e129"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "CHILL ANAESTHESIA LTD."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "52:f5:17:2c:4b:2c:25:8f:5e:33:b7:1c"
      cert_thumbprint     = "02D7035E70CE7BA8E3EB973B32B4C43E8EDA2CC5"
      cert_valid_from     = "2023-07-12"
      cert_valid_to       = "2024-07-12"

      country             = "GB"
      state               = "England"
      locality            = "Bristol"
      email               = "???"
      rdn_serial_number   = "12149989"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "52:f5:17:2c:4b:2c:25:8f:5e:33:b7:1c"
      )
}
