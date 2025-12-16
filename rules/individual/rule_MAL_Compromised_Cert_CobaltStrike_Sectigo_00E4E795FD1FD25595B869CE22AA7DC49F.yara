import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_00E4E795FD1FD25595B869CE22AA7DC49F {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-21"
      version             = "1.0"

      hash                = "b5242d61a1a04f86e7e6f3f9724796497c3391bf7adde9a171f61b02084e5bdd"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "OASIS COURT LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f"
      cert_thumbprint     = "269F25E6B7C690AE094086BD7825D03B48D4FCB1"
      cert_valid_from     = "2020-12-21"
      cert_valid_to       = "2021-12-21"

      country             = "GB"
      state               = "Essex"
      locality            = "Colchester"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f"
      )
}
