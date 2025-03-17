export function parseSimpleYaml(text) {
  const result = {};
  const lines = text.split('\n');
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    
    // Skip empty lines and comments
    if (trimmedLine === '' || trimmedLine.startsWith('#')) {
      continue;
    }
    
    // Look for key-value pairs
    if (trimmedLine.includes(':')) {
      const colonIndex = trimmedLine.indexOf(':');
      const key = trimmedLine.substring(0, colonIndex).trim();
      const value = trimmedLine.substring(colonIndex + 1).trim();
      
      // Store value as string
      result[key] = value;
    }
  }
  
  return result;
}