import GlassSurface from './GlassSurface'

export default function GlassCard({
    children,
    className = '',
    style = {},
    borderRadius = 22,
    borderWidth = 0.06,
    brightness = 50,
    opacity = 0.85,
    blur = 2,
    displace = 0,
    backgroundOpacity = 0,
    saturation = 1.15,
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
                border: '2px solid rgba(255, 255, 255, 0.16)',
                boxShadow: '0 20px 48px rgba(0, 0, 0, 0.35)',
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

