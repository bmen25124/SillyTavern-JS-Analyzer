import Parser from 'tree-sitter';
import JavaScript from 'tree-sitter-javascript';

export interface SecurityViolation {
  type: string;
  node: string;
  position: { row: number; column: number };
  severity: 'error' | 'warning';
  message: string;
}

export interface SecurityAnalysisResult {
  safe: boolean;
  violations: SecurityViolation[];
  sanitizedCode?: string;
}

/**
 * JavaScript Security Analyzer using Tree-sitter
 */
interface SecuritySettings {
  enableJSAnalysis: boolean;
  allowedAPIs: string[];
  blockedAPIs: string[];
  maxScriptLength: number;
  allowObfuscation: boolean;
  debugMode?: boolean;
}

export class JavaScriptSecurityAnalyzer {
  private parser: Parser;
  private dangerousAPIs: Set<string>;
  private dangerousConstructors: Set<string>;
  private settings: SecuritySettings;

  constructor(settings?: Partial<SecuritySettings>) {
    this.parser = new Parser();
    this.parser.setLanguage(JavaScript);

    // Default settings
    this.settings = {
      enableJSAnalysis: true,
      allowedAPIs: ['console', 'Math', 'Date', 'JSON', 'parseInt', 'parseFloat', 'isNaN', 'isFinite'],
      blockedAPIs: ['fetch', 'XMLHttpRequest', 'eval', 'Function', 'WebSocket', 'localStorage', 'sessionStorage'],
      maxScriptLength: 50000,
      allowObfuscation: false,
      debugMode: false,
      ...settings,
    };

    // Define dangerous APIs to block (merge with custom blocked APIs)
    this.dangerousAPIs = new Set([
      ...this.settings.blockedAPIs,
      'indexedDB',
      'navigator.sendBeacon',
      'navigator.geolocation',
      'navigator.getUserMedia',
      'window.open',
      'window.location',
      'document.cookie',
      'document.domain',
      'import',
      'require',
      'importScripts',
      'postMessage',
    ]);

    this.dangerousConstructors = new Set([
      'XMLHttpRequest',
      'WebSocket',
      'Function',
      'Worker',
      'SharedWorker',
      'ServiceWorker',
      'EventSource',
      'WebRTC',
      'AudioContext',
    ]);
  }

  updateSettings(newSettings: Partial<SecuritySettings>): void {
    this.settings = { ...this.settings, ...newSettings };

    // Update dangerous APIs set
    this.dangerousAPIs = new Set([
      ...this.settings.blockedAPIs,
      'indexedDB',
      'navigator.sendBeacon',
      'navigator.geolocation',
      'navigator.getUserMedia',
      'window.open',
      'window.location',
      'document.cookie',
      'document.domain',
      'import',
      'require',
      'importScripts',
      'postMessage',
    ]);
  }

  analyzeScript(code: string): SecurityAnalysisResult {
    const violations: SecurityViolation[] = [];

    try {
      // Skip analysis if disabled
      if (!this.settings.enableJSAnalysis) {
        return { safe: true, violations: [], sanitizedCode: code };
      }

      // Basic length check
      if (code.length > this.settings.maxScriptLength) {
        violations.push({
          type: 'script_too_large',
          node: 'script',
          position: { row: 0, column: 0 },
          severity: 'error',
          message: `Script exceeds maximum allowed length (${this.settings.maxScriptLength} characters)`,
        });
        return { safe: false, violations };
      }

      const tree = this.parser.parse(code);
      this.walkTree(tree.rootNode, violations, code);

      // Check for obfuscation patterns
      this.checkObfuscation(code, violations);

      // Always provide sanitized code, regardless of safety status
      const sanitizedCode = this.sanitizeCode(code, violations);

      if (violations.some((v) => v.severity === 'error')) {
        return { safe: false, violations, sanitizedCode };
      }

      // If safe or only warnings
      return { safe: true, violations, sanitizedCode };
    } catch (error) {
      violations.push({
        type: 'parse_error',
        node: 'root',
        position: { row: 0, column: 0 },
        severity: 'error',
        message: `Failed to parse JavaScript: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });
      return { safe: false, violations };
    }
  }

  private walkTree(node: any, violations: SecurityViolation[], sourceCode: string, depth: number = 0): void {
    const log = this.getASTDebugInfo(sourceCode);
    if (this.settings.debugMode) {
      console.log(this.prettyPrintNode(node, sourceCode, depth));
    }

    // Check for parse errors
    if (node.type === 'ERROR') {
      violations.push({
        type: 'parse_error',
        node: 'syntax_error',
        position: { row: node.startPosition.row, column: node.startPosition.column },
        severity: 'error',
        message: 'Invalid JavaScript syntax detected',
      });
    }

    // Check function calls
    if (node.type === 'call_expression') {
      const callee = this.getCalleeText(node, sourceCode);
      if (this.isDangerousAPI(callee)) {
        violations.push({
          type: 'dangerous_api_call',
          node: callee,
          position: { row: node.startPosition.row, column: node.startPosition.column },
          severity: 'error',
          message: `Blocked dangerous API call: ${callee}`,
        });
      }

      // Check for dynamic evaluation
      if (callee === 'eval' || callee.includes('eval')) {
        violations.push({
          type: 'dynamic_evaluation',
          node: callee,
          position: { row: node.startPosition.row, column: node.startPosition.column },
          severity: 'error',
          message: 'Dynamic code evaluation is not allowed',
        });
      }
    }

    // Check member expressions (like window.location) - but not if they're part of a call expression
    if (node.type === 'member_expression' && node.parent?.type !== 'call_expression') {
      const memberText = this.getMemberText(node, sourceCode);
      if (this.isDangerousAPI(memberText)) {
        violations.push({
          type: 'dangerous_member_access',
          node: memberText,
          position: { row: node.startPosition.row, column: node.startPosition.column },
          severity: 'error',
          message: `Blocked dangerous member access: ${memberText}`,
        });
      }
    }

    // Check new expressions
    if (node.type === 'new_expression') {
      const constructorName = this.getConstructorText(node, sourceCode);
      if (this.dangerousConstructors.has(constructorName)) {
        violations.push({
          type: 'dangerous_constructor',
          node: constructorName,
          position: { row: node.startPosition.row, column: node.startPosition.column },
          severity: 'error',
          message: `Blocked dangerous constructor: ${constructorName}`,
        });
      }
    }

    // Check for assignment to dangerous properties
    if (node.type === 'assignment_expression') {
      const leftSide = this.getAssignmentTarget(node, sourceCode);
      if (leftSide && this.isDangerousAssignment(leftSide)) {
        violations.push({
          type: 'dangerous_assignment',
          node: leftSide,
          position: { row: node.startPosition.row, column: node.startPosition.column },
          severity: 'error',
          message: `Blocked dangerous assignment: ${leftSide}`,
        });
      }
    }

    // Recursively check children
    for (let i = 0; i < node.childCount; i++) {
      this.walkTree(node.child(i), violations, sourceCode, depth + 1);
    }
  }

  private checkObfuscation(code: string, violations: SecurityViolation[]): void {
    // Skip obfuscation check if allowed
    if (this.settings.allowObfuscation) {
      return;
    }

    // Check for common obfuscation patterns
    const obfuscationPatterns = [
      /\\x[0-9a-fA-F]{2}/, // Hex encoding
      /\\u[0-9a-fA-F]{4}/, // Unicode encoding
      /String\.fromCharCode/, // Character code conversion
      /atob|btoa/, // Base64 encoding/decoding
      /unescape|escape/, // URL encoding
    ];

    obfuscationPatterns.forEach((pattern, index) => {
      if (pattern.test(code)) {
        violations.push({
          type: 'obfuscation_detected',
          node: 'obfuscated_code',
          position: { row: 0, column: 0 },
          severity: 'error', // Changed to error since obfuscation is not allowed by default
          message: `Obfuscation detected and blocked (pattern ${index + 1})`,
        });
      }
    });
  }

  private getCalleeText(node: any, sourceCode: string): string {
    if (!node.firstChild) return '';

    if (node.firstChild.type === 'identifier') {
      return sourceCode.slice(node.firstChild.startIndex, node.firstChild.endIndex);
    }
    if (node.firstChild.type === 'member_expression') {
      return this.getMemberText(node.firstChild, sourceCode);
    }
    return '';
  }

  private getMemberText(node: any, sourceCode: string): string {
    if (node.childCount < 3) return '';

    // For member_expression, the structure is: <object> . <property>
    // We need the first child (object) and the third child (property)
    const objectNode = node.child(0);
    const propertyNode = node.child(2);

    if (!objectNode || !propertyNode) return '';

    const object = sourceCode.slice(objectNode.startIndex, objectNode.endIndex);
    const property = sourceCode.slice(propertyNode.startIndex, propertyNode.endIndex);
    return `${object}.${property}`;
  }

  private getConstructorText(node: any, sourceCode: string): string {
    // For new_expression, the structure is: new <constructor> <arguments>
    // We need to get the second child (constructor), not the first (which is 'new')
    if (node.childCount < 2) return '';
    const constructorNode = node.child(1); // Second child is the constructor
    if (!constructorNode) return '';
    return sourceCode.slice(constructorNode.startIndex, constructorNode.endIndex);
  }

  private getAssignmentTarget(node: any, sourceCode: string): string {
    if (!node.firstChild) return '';
    return sourceCode.slice(node.firstChild.startIndex, node.firstChild.endIndex);
  }

  private isDangerousAPI(apiName: string): boolean {
    // Check exact match
    if (this.dangerousAPIs.has(apiName)) {
      return true;
    }

    // Check if the base object (before first dot) is dangerous
    const baseObject = apiName.split('.')[0];
    if (this.dangerousAPIs.has(baseObject)) {
      return true;
    }

    // Check if the final property (after last dot) is dangerous
    const finalProperty = apiName.split('.').pop() || '';
    if (this.dangerousAPIs.has(finalProperty)) {
      return true;
    }

    // Check for eval or Function
    return apiName.includes('eval') || apiName.includes('Function');
  }

  private isDangerousAssignment(target: string): boolean {
    const dangerousAssignments = [
      'window.location',
      'document.location',
      'location.href',
      'document.cookie',
      'document.domain',
    ];
    return dangerousAssignments.some((dangerous) => target.includes(dangerous));
  }

  private sanitizeCode(code: string, violations: SecurityViolation[]): string {
    let sanitized = code;

    // Sort violations by position (reverse order to maintain positions)
    const errorViolations = violations
      .filter((v) => v.severity === 'error')
      .sort((a, b) => b.position.row - a.position.row || b.position.column - a.position.column);

    // Replace dangerous calls with safe alternatives or comments
    errorViolations.forEach((violation) => {
      const replacement = this.getSafeReplacement(violation.node);
      // Simple replacement - in a real implementation, you'd want more sophisticated AST-based replacement
      const escapedNode = violation.node.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      sanitized = sanitized.replace(new RegExp(`\\b${escapedNode}\\b`, 'g'), replacement);
    });

    return sanitized;
  }

  private getSafeReplacement(dangerousAPI: string): string {
    const replacements: Record<string, string> = {
      fetch: '/* fetch() blocked for security */',
      XMLHttpRequest: '/* XMLHttpRequest blocked for security */',
      eval: '/* eval() blocked for security */',
      setTimeout: '/* setTimeout() blocked for security */',
      setInterval: '/* setInterval() blocked for security */',
      localStorage: '/* localStorage blocked for security */',
      sessionStorage: '/* sessionStorage blocked for security */',
      'window.location': '/* window.location blocked for security */',
      'document.cookie': '/* document.cookie blocked for security */',
      'window.open': '/* window.open() blocked for security */',
    };
    return replacements[dangerousAPI] || `/* ${dangerousAPI} blocked for security */`;
  }

  /**
   * Pretty print a Tree-sitter node with detailed information
   * Returns the formatted string instead of logging to console
   */
  private prettyPrintNode(node: any, sourceCode: string, depth: number = 0): string {
    const indent = '  '.repeat(depth);
    const nodeText = sourceCode.slice(node.startIndex, node.endIndex);
    const truncatedText = nodeText.length > 50 ? nodeText.substring(0, 50) + '...' : nodeText;

    const lines = [
      `${indent}Node Type: ${node.type}`,
      `${indent}Start Index: ${node.startIndex}`,
      `${indent}End Index: ${node.endIndex}`,
      `${indent}Position: ${node.startPosition.row}:${node.startPosition.column} - ${node.endPosition.row}:${node.endPosition.column}`,
      `${indent}Text: "${truncatedText.replace(/\n/g, '\\n')}"`,
      `${indent}Child Count: ${node.childCount}`,
    ];

    if (node.isNamed) {
      lines.push(`${indent}Named: true`);
    }

    if (node.hasError) {
      lines.push(`${indent}Has Error: true`);
    }

    if (node.isMissing) {
      lines.push(`${indent}Missing: true`);
    }

    lines.push(`${indent}---`);

    return lines.join('\n');
  }

  /**
   * Get pretty printed AST as a string for debugging
   */
  public getASTDebugInfo(code: string): string {
    if (!this.settings.debugMode) {
      return 'Debug mode is disabled. Enable debugMode in settings to see AST information.';
    }

    try {
      const tree = this.parser.parse(code);
      const debugInfo: string[] = ['=== AST Pretty Print ==='];
      this.collectNodeInfo(tree.rootNode, code, debugInfo);
      return debugInfo.join('\n');
    } catch (error) {
      return `Error parsing code: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }

  /**
   * Collect node information recursively for debug output
   */
  private collectNodeInfo(node: any, sourceCode: string, output: string[], depth: number = 0): void {
    output.push(this.prettyPrintNode(node, sourceCode, depth));

    // Recursively collect children
    for (let i = 0; i < node.childCount; i++) {
      this.collectNodeInfo(node.child(i), sourceCode, output, depth + 1);
    }
  }
}
