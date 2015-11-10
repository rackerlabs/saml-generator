package com.rackspace.saml;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;


public class Main {

    public static void main(String[] args) {
        try {
            Logger logger = LoggerFactory.getLogger(Main.class);

            HashMap<String, List<String>> attributes = new HashMap<String, List<String>>();
            DateTimeFormatter df = ISODateTimeFormat.dateTime();
            String issuer = null;
            String subject = null;
            String privateKey = null;
            String publicKey = null;
            Integer samlAssertionExpirationDays = null;
            Integer samlAssertionExpirationSeconds = null;
            String issueDateAssertionToSet = null;
            String issueDateResponseToSet = null;
            String expirationDateToSet = null;
            String authInstantDateToSet = null;
            String defaultDateToSet = null;
            String credentialType = null;
            DateTime defaultDateTime = null;
            Response responseInitial = null;

            Options options = new Options();
            options.addOption("issuer", true, "Issuer for saml assertion");
            options.addOption("subject", true, "Subject of saml assertion");
            options.addOption("email", true, "Email associated with the subject");
            options.addOption("domain", true, "Domain attribute");
            options.addOption("roles", true, "Comma separated list of roles");
            options.addOption("publicKey", true, "Location of public key to decrypt assertion");
            options.addOption("privateKey", true, "Location or private key use to sign assertion");
            options.addOption("samlAssertionExpirationDays", true, "How long before assertion is no longer valid. Can be negative.");
            options.addOption("samlAssertionExpirationSeconds", true, "How long before assertion is no longer valid. Can be negative.");
            options.addOption("issueDateAssertionToSet", true, "Datetime to set issue date on assertion");
            options.addOption("issueDateResponseToSet", true, "Datetime to set issue date on response");
            options.addOption("expirationDateToSet", true, "Datetime to set expiration date");
            options.addOption("authInstantDateToSet", true, "Datetime to set auth instant");
            options.addOption("defaultDateToSet", true, "Datetime to set for default");
            options.addOption("credentialType", true, "Credential type to set: password or token");

            CommandLineParser parser = new GnuParser();
            CommandLine cmd = parser.parse(options, args);

            if (args.length == 0) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp( "saml-util-1.0", options, true);
                System.exit(1);
            }

            issuer = cmd.getOptionValue("issuer");
            subject = cmd.getOptionValue("subject");
            privateKey = cmd.getOptionValue("privateKey");
            publicKey = cmd.getOptionValue("publicKey");
            samlAssertionExpirationDays = cmd.getOptionValue("samlAssertionExpirationDays") != null ? Integer.valueOf(cmd.getOptionValue("samlAssertionExpirationDays")) : null;
            samlAssertionExpirationSeconds = cmd.getOptionValue("samlAssertionExpirationSeconds") != null ? Integer.valueOf(cmd.getOptionValue("samlAssertionExpirationSeconds")) : null;
            issueDateAssertionToSet = cmd.getOptionValue("issueDateAssertionToSet");
            issueDateResponseToSet = cmd.getOptionValue("issueDateResponseToSet");
            expirationDateToSet = cmd.getOptionValue("expirationDateToSet");
            authInstantDateToSet = cmd.getOptionValue("authInstantDateToSet");
            defaultDateToSet = cmd.getOptionValue("defaultDateToSet");
            credentialType = cmd.getOptionValue("credentialType", "password");

            if (cmd.getOptionValue("domain") != null)
                attributes.put("domain", Arrays.asList(cmd.getOptionValue("domain")));

            if (cmd.getOptionValue("roles") != null)
                attributes.put("roles", Arrays.asList(cmd.getOptionValue("roles").split(",")));

            if (cmd.getOptionValue("email") != null)
                attributes.put("email", Arrays.asList(cmd.getOptionValue("email")));

            SamlAssertionProducer producer = new SamlAssertionProducer();
            producer.setPrivateKeyLocation(privateKey);
            producer.setPublicKeyLocation(publicKey);

            if (authInstantDateToSet != null)
                defaultDateTime = df.parseDateTime(authInstantDateToSet);
            else if (defaultDateToSet != null)
                defaultDateTime = df.parseDateTime(defaultDateToSet);
            else
                defaultDateTime = new DateTime();

            responseInitial = producer.createSAMLResponse(
                    subject, defaultDateTime, credentialType, attributes, issuer,
                    samlAssertionExpirationDays, samlAssertionExpirationSeconds,
                    issueDateAssertionToSet, issueDateResponseToSet, expirationDateToSet, defaultDateToSet
            );

            ResponseMarshaller marshaller = new ResponseMarshaller();
            Element element = marshaller.marshall(responseInitial);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            XMLHelper.writeNode(element, baos);
            String responseStr = new String(baos.toByteArray());

            System.out.println(responseStr);

        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}
