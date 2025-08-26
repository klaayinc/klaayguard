import klaayLogo from "../../icons/KLAAY-LOGO-RGB_ICON.png";

export default function GridShape() {
  return (
    <div className="flex flex-col items-center justify-center h-full">
      <img
        src={klaayLogo}
        alt="Klaay Logo"
        className="w-64 h-64 sm:w-80 sm:h-80 md:w-96 md:h-96 object-contain mb-2"
      />
      <h1 className="text-center text-4xl sm:text-5xl md:text-6xl text-white dark:text-white">
        KlaayGuard
      </h1>
    </div>
  );
}
