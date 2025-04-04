package com.wpanther.eidasremotesigning.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * Utility class for handling different document formats
 * and calculating appropriate digest values
 */
@Component
@Slf4j
public class DocumentFormatUtil {

    // Common MIME types and their signatures
    private static final Map<String, byte[]> FILE_SIGNATURES = new HashMap<>();
    
    static {
        // PDF signature: %PDF
        FILE_SIGNATURES.put("application/pdf", new byte[] { 0x25, 0x50, 0x44, 0x46 });
        
        // XML signature: <?xml or <tag
        FILE_SIGNATURES.put("application/xml", new byte[] { 0x3C, 0x3F, 0x78, 0x6D, 0x6C });
        FILE_SIGNATURES.put("text/xml", new byte[] { 0x3C, 0x3F, 0x78, 0x6D, 0x6C });
        
        // Add more signatures as needed
    }
    
    /**
     * Detects the MIME type of a document based on its content
     * 
     * @param data The document content as a byte array
     * @return The detected MIME type, or "application/octet-stream" if unknown
     */
    public String detectMimeType(byte[] data) {
        if (data == null || data.length < 4) {
            return "application/octet-stream";
        }
        
        // Check for PDF
        if (matchesSignature(data, FILE_SIGNATURES.get("application/pdf"))) {
            return "application/pdf";
        }
        
        // Check for XML
        if (isXml(data)) {
            return "application/xml";
        }
        
        // Default to octet-stream for unknown types
        return "application/octet-stream";
    }
    
    /**
     * Checks if a document matches a file signature
     */
    private boolean matchesSignature(byte[] data, byte[] signature) {
        if (signature == null || data.length < signature.length) {
            return false;
        }
        
        return Arrays.equals(Arrays.copyOfRange(data, 0, signature.length), signature);
    }
    
    /**
     * Checks if content is XML by looking for XML declaration or root tag
     */
    private boolean isXml(byte[] data) {
        // Convert to string for easier checking
        String start = new String(Arrays.copyOfRange(data, 0, Math.min(100, data.length)));
        return start.trim().startsWith("<?xml") || start.trim().startsWith("<");
    }
    
    /**
     * Calculates the digest value for a document using the specified algorithm
     * 
     * @param data The document content as a byte array
     * @param algorithm The digest algorithm (SHA-256, SHA-384, SHA-512)
     * @return The calculated digest as a byte array
     * @throws NoSuchAlgorithmException If the digest algorithm is not supported
     */
    public byte[] calculateDigest(byte[] data, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest.digest(data);
    }
    
    /**
     * Extracts the document type (XAdES, PAdES) based on the MIME type
     * 
     * @param mimeType The MIME type of the document
     * @return The corresponding signature type, or null if not supported
     */
    public String determineSignatureType(String mimeType) {
        if (mimeType == null) {
            return null;
        }
        
        switch (mimeType.toLowerCase()) {
            case "application/pdf":
                return "PADES";
            case "application/xml":
            case "text/xml":
                return "XADES";
            default:
                return null;
        }
    }
    
    /**
     * Validates if a document is suitable for the specified signature type
     * 
     * @param data The document content
     * @param signatureType The target signature type (XADES, PADES)
     * @return true if the document is valid for the signature type, false otherwise
     */
    public boolean validateDocumentForSignatureType(byte[] data, String signatureType) {
        if (data == null || signatureType == null) {
            return false;
        }
        
        String mimeType = detectMimeType(data);
        String detectedType = determineSignatureType(mimeType);
        
        return signatureType.equalsIgnoreCase(detectedType);
    }
    
    /**
     * Validates a PDF document's structure
     * 
     * @param pdfData The PDF document content
     * @return true if the PDF is valid, false otherwise
     */
    public boolean validatePdfDocument(byte[] pdfData) {
        try (InputStream is = new ByteArrayInputStream(pdfData)) {
            // Check PDF header
            byte[] header = new byte[5];
            if (is.read(header) != 5) {
                return false;
            }
            
            String headerStr = new String(header);
            if (!headerStr.equals("%PDF-")) {
                return false;
            }
            
            // Check for EOF marker
            // This is a simplified check; a real implementation would be more thorough
            String content = new String(pdfData);
            return content.contains("%%EOF");
            
        } catch (IOException e) {
            log.error("Error validating PDF document", e);
            return false;
        }
    }
    
    /**
     * Validates an XML document's structure
     * 
     * @param xmlData The XML document content
     * @return true if the XML is well-formed, false otherwise
     */
    public boolean validateXmlDocument(byte[] xmlData) {
        try {
            // Use Java's built-in XML parsing to validate well-formedness
            javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            builder.parse(new ByteArrayInputStream(xmlData));
            
            // If we get here, the XML is well-formed
            return true;
        } catch (Exception e) {
            log.error("Error validating XML document", e);
            return false;
        }
    }
}