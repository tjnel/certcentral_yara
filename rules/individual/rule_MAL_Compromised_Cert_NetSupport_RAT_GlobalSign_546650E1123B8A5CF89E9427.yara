import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_546650E1123B8A5CF89E9427 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-04"
      version             = "1.0"

      hash                = "3d47aa3f5d36514cf264d75f75774318f4a00f8258c73f61631f995613f7290d"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "DAMOKLES SECURITY INNOVATIONS LTD."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "54:66:50:e1:12:3b:8a:5c:f8:9e:94:27"
      cert_thumbprint     = "66CEECE185E725DD4E86433BD4AC28B87115FAB8"
      cert_valid_from     = "2022-03-04"
      cert_valid_to       = "2023-03-05"

      country             = "CA"
      state               = "Alberta"
      locality            = "Airdrie"
      email               = "A.Campbell@guarantaccess.com"
      rdn_serial_number   = "2120160458"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "54:66:50:e1:12:3b:8a:5c:f8:9e:94:27"
      )
}
