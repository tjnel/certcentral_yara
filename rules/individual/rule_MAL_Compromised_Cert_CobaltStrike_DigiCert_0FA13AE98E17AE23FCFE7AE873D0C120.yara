import "pe"

rule MAL_Compromised_Cert_CobaltStrike_DigiCert_0FA13AE98E17AE23FCFE7AE873D0C120 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-13"
      version             = "1.0"

      hash                = "9c3b7ba8d375f19993312a6ac20418e0d107d73b30d585e9ad3646e150ff7c5a"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "KLAKSON, LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20"
      cert_thumbprint     = "A9EB61783FABE97AA1040103430EB8269D443B0A"
      cert_valid_from     = "2020-08-13"
      cert_valid_to       = "2021-07-14"

      country             = "RU"
      state               = "???"
      locality            = "Balashikha"
      email               = "???"
      rdn_serial_number   = "1045002450350"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20"
      )
}
