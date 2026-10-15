import { NextResponse } from "next/server"
import { db } from "@/lib/db"
import { hashPassword, createSessionToken, setSessionCookie } from "@/lib/auth"
import { RegisterSchema } from "@/lib/validation"

export async function POST(req: Request) {
  try {
    const body = await req.json()
    const parsed = RegisterSchema.safeParse(body)
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.errors[0].message }, { status: 400 })
    }

    const { name, email, password } = parsed.data

    const existingUser = await db.user.findUnique({
      where: { email: email.toLowerCase() },
    })

    if (existingUser) {
      return NextResponse.json({ error: "User with this email already exists" }, { status: 409 })
    }

    const passwordHash = await hashPassword(password)
    const user = await db.user.create({
      data: {
        name,
        email: email.toLowerCase(),
        passwordHash,
      },
    })

    const token = await createSessionToken({
      userId: user.id,
      email: user.email,
      name: user.name,
    })

    await setSessionCookie(token)

    return NextResponse.json({
      success: true,
      user: { id: user.id, name: user.name, email: user.email },
    })
  } catch (error) {
    console.error("Register error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
