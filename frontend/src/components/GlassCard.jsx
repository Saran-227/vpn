import GlassSurface from './GlassSurface'

export default function GlassCard({
    children,
    className = '',
    style = {},
    borderRadius = 20,
    borderWidth = 0.05,
    brightness = 50,
    opacity = 0.85,
    blur = 0,
    displace = 0,
    backgroundOpacity = 0,
    saturation = 1.0,
    distortionScale = -180,
    ...props
}) {
    return (
        <GlassSurface
            width="100%"
            height="auto"
            borderRadius={borderRadius}
            borderWidth={borderWidth}
            brightness={brightness}
            opacity={opacity}
            blur={blur}
            displace={displace}
            backgroundOpacity={backgroundOpacity}
            saturation={saturation}
            distortionScale={distortionScale}
            className={`glass-card ${className}`}
            style={{
                border: '1px solid rgba(255, 255, 255, 0.14)',
                boxShadow: '0 16px 40px rgba(0, 0, 0, 0.25)',
                transform: 'translate3d(0, 0, 0)',
                WebkitTransform: 'translate3d(0, 0, 0)',
                backfaceVisibility: 'hidden',
                WebkitBackfaceVisibility: 'hidden',
                contain: 'paint',
                ...style,
            }}
            {...props}
        >
            {children}
        </GlassSurface>
    )
}

