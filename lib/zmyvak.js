const BAD_TAGS = new Set(['SCRIPT', 'STYLE', 'LINK', 'OBJECT', 'EMBED', 'IFRAME', 'FRAME', 'HTML', 'BASE', 'META']);
const BAD_SCRIPT_ATTRIBUTES = new Set([
  'src',
  'dynsrc',
  'lowsrc',
  'href',
  'content',
  'xlink:href',
  'formaction',
  'action',
  'data', // object tag - can load external resources
  'poster', // video tag - can use javascript: protocol
  'background', // body, table, td, th - can use javascript: in older browsers
  'code', // applet, object - can load code
  'codebase', // object, applet - specifies base URL for code
  'cite', // blockquote, q, ins, del - references external resources
  'longdesc', // img - deprecated but still supported
  'usemap', // img, object - can reference javascript: URLs
  'srcdoc', // iframe - inline HTML content (very dangerous)
  'ping', // a, area - sends requests to arbitrary URLs
  'icon', // command - deprecated but exists
  'manifest', // html - offline web application manifest
  'archive', // applet, object - comma-separated URLs
  'classid', // object - identifies class
  'profile' // head - metadata profiles
]);

// based on: https://www.npmjs.com/package/simple-sanitize-html
export default function sanitizeHTML(html, { badTags = BAD_TAGS, badScriptAttributes = BAD_SCRIPT_ATTRIBUTES } = {}) {
  if (!html.includes('<')) {
    return html;
  }
  const div = document.createElement('div');
  div.innerHTML = html;

  for (const node of div.querySelectorAll('*').values()) {
    if (badTags.has(node.tagName.toUpperCase())) {
      node.remove();
      continue;
    }

    for (const attr of node.getAttributeNames()) {
      if (attr.startsWith('on')) {
        node.removeAttribute(attr);
      }

      if (badScriptAttributes.has(attr) && badAttributeValue(node.getAttribute(attr))) {
        node.removeAttribute(attr);
      }
    }
  }

  const result = div.innerHTML;
  div.remove();
  return result;
}

function badAttributeValue(val) {
  const v = val.replace(/\s/g, '').toLowerCase();
  return v.includes('javascript:') || v.includes('vbscript');
}
