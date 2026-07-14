import SwiftUI

extension Color {
    static let myCanvas = Color(red: 14/255, green: 18/255, blue: 25/255)
    static let mySidebar = Color(red: 18/255, green: 23/255, blue: 32/255)
    static let mySurface = Color(red: 25/255, green: 31/255, blue: 43/255)
    static let myRaised = Color(red: 32/255, green: 40/255, blue: 54/255)
    static let myBorder = Color(red: 48/255, green: 58/255, blue: 74/255)
    static let myText = Color(red: 239/255, green: 243/255, blue: 240/255)
    static let myMuted = Color(red: 145/255, green: 156/255, blue: 170/255)
    static let myMoss = Color(red: 118/255, green: 184/255, blue: 154/255)
    static let mySpore = Color(red: 226/255, green: 183/255, blue: 105/255)
    static let myDanger = Color(red: 232/255, green: 121/255, blue: 121/255)
}

struct NodeMark: View {
    var size: CGFloat = 58

    var body: some View {
        Canvas { context, canvas in
            let points = [
                CGPoint(x: canvas.width * 0.18, y: canvas.height * 0.50),
                CGPoint(x: canvas.width * 0.50, y: canvas.height * 0.20),
                CGPoint(x: canvas.width * 0.82, y: canvas.height * 0.50),
                CGPoint(x: canvas.width * 0.50, y: canvas.height * 0.80),
            ]
            var path = Path()
            path.move(to: points[0])
            points.dropFirst().forEach { path.addLine(to: $0) }
            path.closeSubpath()
            context.stroke(path, with: .color(.myMoss), lineWidth: size * 0.035)
            for (index, point) in points.enumerated() {
                let radius = size * 0.09
                let circle = Path(ellipseIn: CGRect(
                    x: point.x - radius,
                    y: point.y - radius,
                    width: radius * 2,
                    height: radius * 2
                ))
                context.fill(circle, with: .color(index == 2 ? .mySpore : .myMoss))
            }
        }
        .frame(width: size, height: size)
        .accessibilityLabel("Mycellium")
    }
}

struct StatusCard: View {
    let title: String
    let bodyText: String
    let accent: Color

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Circle().fill(accent).frame(width: 10, height: 10).padding(.top, 5)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(bodyText).font(.subheadline).foregroundStyle(Color.myMuted)
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .background(Color.mySurface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

struct InitialAvatar: View {
    let name: String

    var body: some View {
        Text(String(name.trimmingCharacters(in: .whitespacesAndNewlines).first ?? "?" ).uppercased())
            .font(.headline)
            .foregroundStyle(Color.myMoss)
            .frame(width: 44, height: 44)
            .background(Color.myRaised, in: Circle())
    }
}
