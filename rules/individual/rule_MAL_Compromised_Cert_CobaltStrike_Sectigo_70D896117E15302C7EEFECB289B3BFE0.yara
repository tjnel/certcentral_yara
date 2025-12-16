import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_70D896117E15302C7EEFECB289B3BFE0 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-28"
      version             = "1.0"

      hash                = "e1370e9afb0bd1e7fb4cb11779a39b6b2d2e0f99fc2cd6137b2c813a3cd54b70"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Quicktech.com"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "70:d8:96:11:7e:15:30:2c:7e:ef:ec:b2:89:b3:bf:e0"
      cert_thumbprint     = "697D12D05433678457FBB0534239B394E60F783B"
      cert_valid_from     = "2020-09-28"
      cert_valid_to       = "2021-09-28"

      country             = "CA"
      state               = "Alberta"
      locality            = "Calgary"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "70:d8:96:11:7e:15:30:2c:7e:ef:ec:b2:89:b3:bf:e0"
      )
}
