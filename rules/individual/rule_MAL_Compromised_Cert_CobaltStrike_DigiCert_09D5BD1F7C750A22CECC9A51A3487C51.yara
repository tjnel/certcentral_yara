import "pe"

rule MAL_Compromised_Cert_CobaltStrike_DigiCert_09D5BD1F7C750A22CECC9A51A3487C51 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-12"
      version             = "1.0"

      hash                = "780dc4b0fb8ce1983083bdfe875629d2ee66884bf5d634b6c4ef57544f6b2ba1"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Dynamic Digital Marketing Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "09:d5:bd:1f:7c:75:0a:22:ce:cc:9a:51:a3:48:7c:51"
      cert_thumbprint     = "32B2125D6FE4F483A4315476BEE568BA705B39B8"
      cert_valid_from     = "2021-03-12"
      cert_valid_to       = "2022-03-16"

      country             = "CA"
      state               = "Ontario"
      locality            = "Gloucester"
      email               = "???"
      rdn_serial_number   = "1273056-1"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "09:d5:bd:1f:7c:75:0a:22:ce:cc:9a:51:a3:48:7c:51"
      )
}
