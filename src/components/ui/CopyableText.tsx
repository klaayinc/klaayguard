import React, { useState } from "react";
import { MdContentCopy, MdCheck } from "react-icons/md";

interface CopyableTextProps {
  text: string;
  label?: string;
  className?: string;
}

export const CopyableText: React.FC<CopyableTextProps> = ({
  text,
  label = "ID",
  className = "",
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000); // Reset after 2 seconds
    } catch (error) {
      console.error("Failed to copy text:", error);
    }
  };

  return (
    <div className={`flex items-center space-x-2 ${className}`}>
      <span>
        {label}: {text}
      </span>
      <button
        onClick={handleCopy}
        className="text-blue-300 hover:text-blue-200 transition-colors"
        title="Copy to clipboard"
      >
        {copied ? <MdCheck className="text-green-400" /> : <MdContentCopy />}
      </button>
    </div>
  );
};

export default CopyableText;
