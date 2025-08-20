import { useEffect, useRef } from "react";
import ApiEnvToggle from "../components/common/ApiEnvToggle";

// import { Link } from "react-router";

const AppHeader: React.FC = () => {
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "k") {
        event.preventDefault();
        inputRef.current?.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  return (
    <header className="sticky top-0 flex w-full bg-white border-gray-200 z-99999 dark:border-gray-800 dark:bg-gray-900 lg:border-b">
      <div className="flex flex-col items-center justify-between flex-grow lg:flex-row lg:px-6">
        <div
          className={`flex items-center justify-between w-full gap-4 px-5  lg:flex shadow-theme-md sm:justify-start lg:px-0 lg:shadow-none`}
        >
          <p className="text-left">Datalyst</p>
          <div className="ml-auto">
            <ApiEnvToggle />
          </div>
        </div>
      </div>
    </header>
  );
};

export default AppHeader;
