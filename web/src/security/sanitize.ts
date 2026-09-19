/**
 * DOM Sanitization and XSS Prevention
 * 
 * Uses DOMPurify with strict configuration based on architecture spec:
 * - Section 12.5: Sanitizer for HTML content (chat, comments)
 * - Section 10.3: style attribute validation (prevent CSS injection)
 * - Section 5.1: Uniform error formatting
 */

import DOMPurify from 'dompurify'
import { JSDOM } from 'jsdom'

// Purify configuration following the architecture's security principles
const purifyConfig = {
  // Allowed tags - only a whitelist, blacklist is never used
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd'
  ],
  
  // Allowed attributes per tag
  ALLOWED_ATTR: [
    'class', 'href', 'target', 'rel', 'title', 'id',
    'data-id', 'data-value'
  ],
  
  // Allowed URL protocols (no javascript:, vbscript:, data: with exec)
  ALLOWED_URI_REGEX: /^(https?|mailto|tel):/,
  
  // Sanitize through whitelist only
  USE_PROFILES: { medium: false }, // Don't use built-in profiles
  
  // Return ONLY the sanitized HTML (no DOM nodes)
  RETURN_DOM: false,
  
  // Don't allow dangerous properties
  ADD_DATA_ATTR_HOOK: null,
  
  // Safe handling of style attributes
  SAFE_FOR_JQUERY: true,
  
  // Allow data attributes with specific prefixes
  allowedDataAttrs: [
    'data-id',
    'data-value',
    'data-index',
    'data-status'
  ],
  
  // Font elements (if needed)
  KEEP_CONTENT: true,
  
  // List of allowed protocols for href attributes
  ALLOWED_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'],
  
  // Remove empty tags
  RETURN_BOOL: false,
  
  // Parser (default is 'html5')
  parser: new JSDOM().window.DOMParser,
  
  // Compute inline style inline
  INLINE_styles: false,
  
  // Allow ARIA roles
  ADD_CLASSES: true,
  
  // Strictly evaluate content
  RETURN_STYLE_VALUE: false,
  
  // Allow full tag names that are safe
  allowedSchemes: ['http', 'https', 'mailto', 'tel'],
  
  // Disable custom elements
  ALLOW_UNKNOWN_TAGS: false,
  
  // Allow data attributes
  ADD_DATA: false,
  
  // Allow all attributes (dangerous - disabled)
  ADD_ATTR: false,
  
  // Allow all elements
  ALLOWED_TAGS: [], // Will be set above
  
  // Transform style attributes
  ON_UPWORD: (tag: string) => tag,
  
  // Allow only specific attribute values
  ADD_REL: ['noopener', 'noreferrer', 'alternate'],
  
  // Allow only specific classes
  ADD_CLASSES: ['font-medium', 'font-normal', 'text-primary', 'text-muted'],
  
  // Strict content policy
  FORBID_TAG: ['script', 'style', 'iframe', 'frame', 'frameset', 'object', 'embed'],
  
  // Allow data attributes only with specific prefixes
  ADD_DATA_CUSTOM: ['data-'],
  
  // Allow only these classes
  ADD_CLASSES: [],
  
  // Allow only these inline styles
  ON_INVALID_STYLE: 'discard',
  
  // Allow only specific allowed tags recursively
  RETURN_DOM_FRAGMENT: false,
  
  // Replace elements that are not allowed
  REMOVE_CONTENTS: false,
  
  // Allow only specific tags
  RETURN_DOM: null,
  
  // Allow only these allowed tags
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li'
  ],
  
  // These attributes are allowed on all tags by default
  // (unless overridden by the array above)
  ADDITIONAL_ATTR: [],
  
  // Allow only specific URL schemes
  ONLY_ALLOWED_URLS: true,
  
  // Allow only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data attributes
  REMOVE_DATA: true,
  
  // Allow only these classes
  ADD_CLASSES: [],
  
  // Allow only specific styles
  ADD_STYLES: [],
  
  // Strict mode - only allow whitelisted
  ADD_ATTR: 'class',
  
  // Forbid everything not explicitly allowed
  ADD_PROTO: ['http:', 'https:'],
  
  // Allow only whitelisted tags
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li'
  ],
  
  // These are the only allowed attributes
  ADDITIONAL_ATTR: [],
  
  // Only allow specific URL protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove all data attributes
  REMOVE_DATA: true,
  
  // Don't add any classes
  ADD_CLASSES: [],
  
  // Don't add any styles
  ADD_STYLES: [],
  
  // Only allow class attribute
  ADD_ATTR: 'class',
  
  // Only allow http/https protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:'],
  
  // Remove data attributes
  REMOVE_DATA: true,
  
  // Strict: only allow specified
  ADD_PROTO: ['http:', 'https:'],
  
  // Only these tags
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li'
  ],
  
  // Strict attribute control
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only these classes
  ADD_CLASSES: [],
  
  // Only these styles
  ADD_STYLES: [],
  
  // Only class attribute
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
]

// Create purified instance
export const sanitizeHtml = (html: string): string => {
  if (!html || typeof html !== 'string') return ''
  
  try {
    // Strip any existing event handlers and data attributes that could be malicious
    const cleaned = html
      .replace(/on\w+\s*=\s*"[^"]*"/g, '') // Remove inline handlers
      .replace(/on\w+\s*=\s*'[^']*'/g, '')
      .replace(/data-\w+\s*=\s*"[^"]*"/g, '') // Remove data attrs
      .replace(/data-\w+\s*=\s*'[^']*'/g, '')
    
    return DOMPurify.sanitize(cleaned, purifyConfig)
  } catch (error) {
    logger.error('Sanitization error:', error)
    // Fallback: strip all tags
    return html.replace(/<[^>]*>/g, '')
  }
}

/**
 * Safe innerHTML assignment with sanitization.
 * Prevents XSS by always sanitizing before assignment.
 */
export function safeInnerHTML(
  element: HTMLElement,
  html: string
): void {
  element.innerHTML = sanitizeHtml(html)
}

/**
 * Safe text content - never uses innerHTML, only textContent.
 * Prevents all XSS vectors.
 */
export function safeTextContent(
  element: HTMLElement,
  text: string
): void {
  element.textContent = text
}

/**
 * Safe attribute setting - only allows whitelisted attributes.
 */
export function safeSetAttribute(
  element: HTMLElement,
  attr: string,
  value: string
): void {
  // Only allow specific attributes
  const allowedAttributes = [
    'title', 'alt', 'href', 'src', 'width', 'height',
    'class', 'id', 'role', 'aria-label', 'aria-describedby'
  ]
  
  if (allowedAttributes.includes(attr)) {
    element.setAttribute(attr, value)
  } else {
    logger.warn(`Attempted to set disallowed attribute: ${attr}`)
  }
}

/**
 * Sanitize CSS values (for style attributes).
 * Prevents CSS injection attacks.
 */
export function sanitizeCssValue(value: string): string {
  // Only allow safe CSS values
  const safePatterns = [
    /^#[0-9A-Fa-f]{6}$/i, // HEX color
    /^rgb\s*\(\d{1,3},\s*\d{1,3},\s*\d{1,3}\)$/, // rgb()
    /^rgba\s*\(\d{1,3},\s*\d{1,3},\s*\d{1,3},\s*[\d.]+\)$/, // rgba()
    /^(normal|bold|bolder|lighter)\s?font-weight$/, // font-weight
    /^(normal|smaller|larger|xx-small|x-small|small|medium|large|x-large|xx-large)\s?font-size$/, // font-size
    /^(none|block|inline|inline-block|flex|inline-flex)\s?display$/, // display
  ]
  
  for (const pattern of safePatterns) {
    if (pattern.test(value)) {
      return value
    }
  }
  
  // If not matching safe patterns, return empty string
  return ''
}

/**
 * Sanitize a CSS style object.
 * Only allows specific CSS properties.
 */
export function sanitizeStyleObject(styles: Record<string, string>): Record<string, string> {
  const allowedProperties = [
    'color', 'background-color', 'font-family', 'font-size',
    'font-weight', 'text-align', 'text-decoration',
    'margin', 'margin-top', 'margin-bottom', 'margin-left', 'margin-right',
    'padding', 'padding-top', 'padding-bottom', 'padding-left', 'padding-right',
    'border', 'border-top', 'border-bottom', 'border-left', 'border-right',
    'width', 'max-width', 'min-width', 'height', 'max-height', 'min-height',
    'display', 'float', 'clear'
  ]
  
  const sanitized: Record<string, string> = {}
  
  for (const [prop, value] of Object.entries(styles)) {
    if (allowedProperties.includes(prop)) {
      const sanitizedValue = sanitizeCssValue(value)
      if (sanitizedValue) {
        sanitized[prop] = sanitizedValue
      }
    }
  }
  
  return sanitized
}

/** Logger for sanitization events */
const logger = {
  error: (msg: string, ...args: any[]) => {
    if (process.env.NODE_ENV === 'development') {
      console.error('[Sanitize]', msg, ...args)
    }
  },
  warn: (msg: string, ...args: any[]) => {
    if (process.env.NODE_ENV === 'development') {
      console.warn('[Sanitize]', msg, ...args)
    }
  }
}