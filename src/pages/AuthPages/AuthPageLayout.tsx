import React from "react";
import GridShape from "../../components/common/GridShape";
import ThemeTogglerTwo from "../../components/common/ThemeTogglerTwo";
import ApiEnvToggle from "../../components/common/ApiEnvToggle";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="relative p-6 bg-white z-1 dark:bg-gray-900 sm:p-0">
      <div className="relative flex flex-col justify-center w-full h-screen sm:flex-row dark:bg-gray-900 sm:p-0">
        {children}
        <div className="items-center w-full h-full sm:w-1/2 bg-brand-950 dark:bg-white/5 sm:grid">
          <div className="relative flex items-center justify-center z-1">
            {/* <!-- ===== Common Grid Shape Start ===== --> */}
            <GridShape />
            <div className="flex flex-col space-y-10 items-center max-w-xs">
              <p className="text-center text-4xl text-white dark:text-white">
                Klaay Guard
              </p>
            </div>
          </div>
        </div>
        <div className="fixed z-50 hidden bottom-6 right-6 sm:flex sm:flex-col sm:items-end sm:gap-2">
          <ApiEnvToggle />
          <ThemeTogglerTwo />
        </div>
      </div>
    </div>
  );
}
