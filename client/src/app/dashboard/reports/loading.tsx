const Loading = () => {
  const r = 28;
  const circumference = 2 * Math.PI * r;
  const arc = circumference / 3;
  const gap = circumference - arc;

  return (
    <div className="flex min-h-[80dvh] items-center justify-center rounded-lg">
      <div className="relative h-16 w-16">
        {/* Arc = 1/3 of perimeter, slow spin */}
        <svg
          className="h-full w-full animate-[spin_2.5s_linear_infinite]"
          viewBox="0 0 64 64"
        >
          <circle
            cx="32"
            cy="32"
            r={r}
            fill="none"
            stroke="rgba(255,255,255,0.9)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeDasharray={`${arc} ${gap}`}
          />
        </svg>
        {/* Image loading icon in center */}
        <div className="absolute inset-0 flex items-center justify-center">
          <img src="/brand/logo.png" alt="Loading" className="h-8 w-8" />
        </div>
      </div>
    </div>
  );
};

export default Loading;
