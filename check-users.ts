
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function main() {
    const count = await prisma.user.count()
    console.log(`User count: ${count}`)
    if (count > 0) {
        const users = await prisma.user.findMany({ take: 5 })
        console.log('Sample users:', users.map(u => u.username))
    }
}

main()
