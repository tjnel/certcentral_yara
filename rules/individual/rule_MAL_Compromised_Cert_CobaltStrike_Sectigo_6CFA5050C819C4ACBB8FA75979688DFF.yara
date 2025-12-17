import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_6CFA5050C819C4ACBB8FA75979688DFF {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-02"
      version             = "1.0"

      hash                = "2561379ad92527aabb67d7649589e2a3719db5e57f2b451baf57f57258def793"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Elite Web Development Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff"
      cert_thumbprint     = "AD300C8D9631F68DC220F7EF3ADDD40AEE86869E"
      cert_valid_from     = "2020-07-02"
      cert_valid_to       = "2021-07-02"

      country             = "CA"
      state               = "Alberta"
      locality            = "Edmonton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff"
      )
}
